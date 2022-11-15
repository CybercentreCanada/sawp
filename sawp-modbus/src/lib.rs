//! A modbus protocol parser. Given bytes and a [`sawp::parser::Direction`], it will
//! attempt to parse the bytes and return a [`Message`]. The parser will
//! inform the caller about what went wrong if no message is returned (see [`sawp::parser::Parse`]
//! for details on possible return types).
//!
//! The following protocol references were used to create this module:
//!
//! [Modbus_V1_1b](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
//!
//! [PI_MBUS_300](https://modbus.org/docs/PI_MBUS_300.pdf)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_modbus::{Modbus, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let modbus = Modbus::default();
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         // If we know that this is a request or response, change the Direction
//!         // for a more accurate parsing
//!         match modbus.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed modbus message
//!             Ok((rest, Some(message))) => {
//!                 println!("Modbus message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be modbus and made some progress,
//!             // but more bytes are needed
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was modbus or not and more
//!             // bytes are needed
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not modbus
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

#![allow(clippy::unneeded_field_pattern)]

/// Re-export of the `Flags` struct that is used to represent bit flags
/// in this crate.
pub use sawp_flags::{Flag, Flags};

use sawp::error::{Error, ErrorKind, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::{Probe, Status};
use sawp::protocol::Protocol;

use sawp_flags::BitFlags;

use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u8};

use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::ops::RangeInclusive;

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

// Used for exception handling -- any function above this is an exception
const ERROR_MASK: u8 = 0x80;
// Maximum read/write quantity
const MAX_QUANTITY_BIT_ACCESS: u16 = 2000;
const MAX_QUANTITY_WORD_ACCESS: u16 = 125;
// Valid count range for reading
const MIN_RD_COUNT: u8 = 1;
const MAX_RD_COUNT: u8 = 250;

const MIN_LENGTH: u16 = 2;
const MAX_LENGTH: u16 = 254;

/// Function code groups based on general use. Allows for easier
/// parsing of certain functions, since generally most functions in a group
/// will have the same request/response structure.
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, BitFlags)]
pub enum AccessType {
    READ = 0b0000_0001,
    WRITE = 0b0000_0010,
    DISCRETES = 0b0000_0100,
    COILS = 0b0000_1000,
    INPUT = 0b0001_0000,
    HOLDING = 0b0010_0000,
    SINGLE = 0b0100_0000,
    MULTIPLE = 0b1000_0000,
    /// DISCRETES | COILS
    BIT_ACCESS_MASK = 0b0000_1100,
    /// DISCRETES | COILS | INPUT | HOLDING
    FUNC_MASK = 0b0011_1100,
    /// WRITE | SINGLE
    WRITE_SINGLE = 0b0100_0010,
    /// WRITE | MULTIPLE
    WRITE_MULTIPLE = 0b1000_0010,
}

impl From<FunctionCode> for Flags<AccessType> {
    fn from(code: FunctionCode) -> Self {
        match code {
            FunctionCode::RdCoils => AccessType::COILS | AccessType::READ,
            FunctionCode::RdDiscreteInputs => AccessType::DISCRETES | AccessType::READ,
            FunctionCode::RdHoldRegs => AccessType::HOLDING | AccessType::READ,
            FunctionCode::RdInputRegs => AccessType::INPUT | AccessType::READ,
            FunctionCode::WrSingleCoil => AccessType::COILS | AccessType::WRITE_SINGLE,
            FunctionCode::WrSingleReg => AccessType::HOLDING | AccessType::WRITE_SINGLE,
            FunctionCode::WrMultCoils => AccessType::COILS | AccessType::WRITE_MULTIPLE,
            FunctionCode::WrMultRegs => AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
            FunctionCode::MaskWrReg => AccessType::HOLDING | AccessType::WRITE,
            FunctionCode::RdWrMultRegs => {
                AccessType::HOLDING | AccessType::READ | AccessType::WRITE_MULTIPLE
            }
            _ => AccessType::none(),
        }
    }
}

/// Function Code Categories as stated in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, BitFlags)]
pub enum CodeCategory {
    PUBLIC_ASSIGNED = 0b0000_0001,
    PUBLIC_UNASSIGNED = 0b0000_0010,
    USER_DEFINED = 0b0000_0100,
    RESERVED = 0b0000_1000,
}

impl CodeCategory {
    fn from_raw(id: u8) -> Flags<Self> {
        match id {
            0 => CodeCategory::none(),
            x if x < 9 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 15 => CodeCategory::RESERVED.into(),
            x if x < 41 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 43 => CodeCategory::RESERVED.into(),
            x if x < 65 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 73 => CodeCategory::USER_DEFINED.into(),
            x if x < 90 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 92 => CodeCategory::RESERVED.into(),
            x if x < 100 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 111 => CodeCategory::USER_DEFINED.into(),
            x if x < 125 => CodeCategory::PUBLIC_UNASSIGNED.into(),
            x if x < 128 => CodeCategory::RESERVED.into(),
            _ => CodeCategory::none(),
        }
    }
}

impl From<&Message> for Flags<CodeCategory> {
    fn from(msg: &Message) -> Self {
        match msg.function.code {
            FunctionCode::Diagnostic => match &msg.data {
                Data::Diagnostic { func, .. } => {
                    if func.code == DiagnosticSubfunction::Reserved {
                        CodeCategory::RESERVED.into()
                    } else {
                        CodeCategory::PUBLIC_ASSIGNED.into()
                    }
                }
                _ => CodeCategory::none(),
            },
            FunctionCode::MEI => match &msg.data {
                Data::MEI { mei_type, .. } => {
                    if mei_type.code == MEIType::Unknown {
                        CodeCategory::RESERVED.into()
                    } else {
                        CodeCategory::PUBLIC_ASSIGNED.into()
                    }
                }
                _ => CodeCategory::none(),
            },
            FunctionCode::Unknown => CodeCategory::from_raw(msg.function.raw),
            _ => CodeCategory::PUBLIC_ASSIGNED.into(),
        }
    }
}

/// Flags which identify messages which parse as modbus
/// but contain invalid data. The caller can use the message's
/// error flags to see if and what errors were in the
/// pack of bytes and take action using this information.
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, BitFlags)]
pub enum ErrorFlags {
    DATA_VALUE = 0b0000_0001,
    DATA_LENGTH = 0b0000_0010,
    EXC_CODE = 0b0000_0100,
    FUNC_CODE = 0b0000_1000,
    PROTO_ID = 0b0001_0000,
}

/// Information on the function code parsed
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub struct Function {
    /// Value of the function byte
    pub raw: u8,
    /// Function name associated with the raw value
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub code: FunctionCode,
}

impl Function {
    fn new(val: u8) -> Function {
        Function {
            raw: val,
            code: {
                if val >= ERROR_MASK {
                    FunctionCode::from_raw(val ^ ERROR_MASK)
                } else {
                    FunctionCode::from_raw(val)
                }
            },
        }
    }
}

/// Function code names as stated in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum FunctionCode {
    RdCoils = 0x01,
    RdDiscreteInputs,
    RdHoldRegs,
    RdInputRegs,
    WrSingleCoil,
    WrSingleReg,
    RdExcStatus,
    Diagnostic,
    Program484,
    Poll484,
    GetCommEventCtr,
    GetCommEventLog,
    ProgramController,
    PollController,
    WrMultCoils,
    WrMultRegs,
    ReportServerID,
    Program884,
    ResetCommLink,
    RdFileRec,
    WrFileRec,
    MaskWrReg,
    RdWrMultRegs,
    RdFIFOQueue,
    MEI = 0x2b,
    Unknown,
}

impl std::fmt::Display for FunctionCode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl FunctionCode {
    pub fn from_raw(val: u8) -> Self {
        FunctionCode::try_from(val).unwrap_or(FunctionCode::Unknown)
    }
}

/// Information on the diagnostic subfunction code parsed
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub struct Diagnostic {
    /// Value of the subfunction bytes
    pub raw: u16,
    /// Subfunction name associated with the raw value
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub code: DiagnosticSubfunction,
}

impl Diagnostic {
    fn new(val: u16) -> Diagnostic {
        Diagnostic {
            raw: val,
            code: DiagnosticSubfunction::try_from(val).unwrap_or(DiagnosticSubfunction::Reserved),
        }
    }
}

/// Subfunction code names as stated in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum DiagnosticSubfunction {
    RetQueryData = 0x00,
    RestartCommOpt,
    RetDiagReg,
    ChangeInputDelimiter,
    ForceListenOnlyMode,
    // 0x05 - 0x09: RESERVED
    ClearCtrDiagReg = 0x0a,
    RetBusMsgCount,
    RetBusCommErrCount,
    RetBusExcErrCount,
    RetServerMsgCount,
    RetServerNoRespCount,
    RetServerNAKCount,
    RetServerBusyCount,
    RetBusCharOverrunCount,
    RetOverrunErrCount,
    ClearOverrunCounterFlag,
    GetClearPlusStats,
    // 0x16 and on: RESERVED
    Reserved,
}

impl std::fmt::Display for DiagnosticSubfunction {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

/// Information on the mei code parsed
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub struct MEI {
    /// Value of the mei function byte
    pub raw: u8,
    /// Function name associated with the raw value
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub code: MEIType,
}

impl MEI {
    fn new(val: u8) -> MEI {
        MEI {
            raw: val,
            code: MEIType::try_from(val).unwrap_or(MEIType::Unknown),
        }
    }
}

/// MEI function code names as stated in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum MEIType {
    Unknown = 0x00,
    CANOpenGenRefReqResp = 0x0d,
    RdDevId = 0x0e,
}

impl std::fmt::Display for MEIType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

/// Information on the exception code parsed
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub struct Exception {
    /// Value of the exception code byte
    pub raw: u8,
    /// Exception name associated with the raw value
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub code: ExceptionCode,
}

impl Exception {
    fn new(val: u8) -> Exception {
        Exception {
            raw: val,
            code: ExceptionCode::try_from(val).unwrap_or(ExceptionCode::Unknown),
        }
    }
}

/// Exception code names as stated in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum ExceptionCode {
    IllegalFunction = 0x01,
    IllegalDataAddr,
    IllegalDataValue,
    ServerDeviceFail,
    Ack,
    ServerDeviceBusy,
    NegAck,
    MemParityErr,
    GatewayPathUnavailable = 0x0a,
    GatewayTargetFailToResp,
    Unknown,
}

impl std::fmt::Display for ExceptionCode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

/// Read information on parsed in function data
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Clone, Debug, PartialEq)]
pub enum Read {
    Request { address: u16, quantity: u16 },
    Response(Vec<u8>),
}

/// Write information on parsed in function data
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub enum Write {
    /// [`AccessType::MULTIPLE`] requests, responses fall in [`Write::Other`]
    MultReq {
        address: u16,
        quantity: u16,
        data: Vec<u8>,
    },
    /// [`FunctionCode::MaskWrReg`] requests/responses, the only (public) write function
    /// that does not fall under [`AccessType::SINGLE`]/[`AccessType::MULTIPLE`]
    /// (with the exception of [`FunctionCode::WrFileRec`])
    Mask {
        address: u16,
        and_mask: u16,
        or_mask: u16,
    },
    /// Used for [`AccessType::SINGLE`] requests/responses and [`AccessType::MULTIPLE`] responses
    Other { address: u16, data: u16 },
}

/// Represents the various fields found in the PDU
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub enum Data {
    Exception(Exception),
    Diagnostic {
        func: Diagnostic,
        data: Vec<u8>,
    },
    MEI {
        mei_type: MEI,
        data: Vec<u8>,
    },
    Read(Read),
    Write(Write),
    ReadWrite {
        read: Read,
        write: Write,
    },
    /// Used for data that doesn't fit elsewhere
    ByteVec(Vec<u8>),
    Empty,
}

#[derive(Debug, Default)]
pub struct Modbus {
    /// Enable strict probing, such as only recognizing
    /// public assigned function codes
    pub probe_strict: bool,
}

/// Breakdown of the parsed modbus bytes
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_modbus"))]
#[derive(Debug, PartialEq)]
pub struct Message {
    pub transaction_id: u16,
    pub protocol_id: u16,
    length: u16,
    pub unit_id: u8,
    pub function: Function,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u8"))]
    pub access_type: Flags<AccessType>,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u8"))]
    pub category: Flags<CodeCategory>,
    pub data: Data,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u8"))]
    pub error_flags: Flags<ErrorFlags>,
}

impl Message {
    /// Subtracts 2 from the length (the unit id and function bytes)
    /// so that length checks do not need to account for the 2 bytes
    fn data_length(&self) -> u16 {
        self.length - 2
    }

    //          Num Bytes  Byte Placement
    // Code:    1          (0)
    fn parse_exception<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, exc_code) = be_u8(input)?;
        let exc = Exception::new(exc_code);
        match exc.code {
            ExceptionCode::IllegalDataValue
                if self.function.code != FunctionCode::Diagnostic
                    && ((self.function.raw > 6 && self.function.raw < 15)
                        || (self.function.raw > 16 && self.function.raw < 20)) =>
            {
                self.error_flags |= ErrorFlags::EXC_CODE
            }
            ExceptionCode::IllegalDataAddr
                if (self.function.raw > 6 && self.function.raw < 15)
                    || (self.function.raw > 16 && self.function.raw < 20) =>
            {
                self.error_flags |= ErrorFlags::EXC_CODE
            }
            ExceptionCode::MemParityErr
                if self.function.code != FunctionCode::RdFileRec
                    && self.function.code != FunctionCode::WrFileRec =>
            {
                self.error_flags |= ErrorFlags::EXC_CODE
            }
            ExceptionCode::Unknown => self.error_flags |= ErrorFlags::EXC_CODE,
            _ => {}
        }

        self.data = Data::Exception(exc);
        Ok(input)
    }

    //                             Num Bytes   Byte Placement
    // Request:
    //     Diagnostic Code:        2           (0,1)
    //     Data:                   2           (2,3)
    // Response:
    //     Diagnostic Code:        2           (0,1)
    //     Data:                   x           (2..)
    fn parse_diagnostic<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        if self.data_length() < 2 {
            self.error_flags |= ErrorFlags::DATA_LENGTH;
            return Ok(input);
        }

        let (input, diag_func) = be_u16(input)?;
        let (input, rest) = take(self.data_length() - 2)(input)?;

        self.data = Data::Diagnostic {
            func: Diagnostic::new(diag_func),
            data: rest.to_vec(),
        };
        Ok(input)
    }

    //                             Num Bytes   Byte Placement
    //     MEI Code:               2           (0,1)
    //     Data:                   x           (2..)
    fn parse_mei<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        if self.data_length() < 1 {
            self.error_flags |= ErrorFlags::DATA_LENGTH;
            return Ok(input);
        }

        let (input, raw_mei) = be_u8(input)?;
        let mei_type = MEI::new(raw_mei);
        let (input, rest) = take(self.data_length() - 1)(input)?;

        self.data = Data::MEI {
            mei_type,
            data: rest.to_vec(),
        };

        Ok(input)
    }

    fn parse_bytevec<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, data) = take(self.data_length())(input)?;
        self.data = Data::ByteVec(data.to_vec());
        Ok(input)
    }

    //                     Num Bytes   Byte Placement
    // Starting Address:   2           (0,1)
    // Quantity of Regs:   2           (2,3)
    fn parse_read_request<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, address) = be_u16(input)?;
        let (input, quantity) = be_u16(input)?;

        if quantity == 0 {
            self.error_flags |= ErrorFlags::DATA_VALUE;
        }

        if self.function.code != FunctionCode::RdWrMultRegs && self.data_length() > 4 {
            self.error_flags |= ErrorFlags::DATA_LENGTH;
        }

        if self.access_type.intersects(AccessType::BIT_ACCESS_MASK) {
            if quantity > MAX_QUANTITY_BIT_ACCESS {
                self.error_flags |= ErrorFlags::DATA_VALUE;
            }
        } else if quantity > MAX_QUANTITY_WORD_ACCESS {
            self.error_flags |= ErrorFlags::DATA_VALUE;
        }

        self.data = Data::Read(Read::Request { address, quantity });
        Ok(input)
    }

    //          Num Bytes  Byte Placement
    // Count:   1          (0)
    // Data:    Count      (1..Count + 1)
    fn parse_read_response<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        if self.data_length() < 1 {
            self.error_flags |= ErrorFlags::DATA_LENGTH;
            return Ok(input);
        }

        let (input, count) = be_u8(input)?;

        if !(MIN_RD_COUNT..=MAX_RD_COUNT).contains(&count) {
            self.error_flags |= ErrorFlags::DATA_VALUE;
        }

        if self.data_length() - 1 != count.into() {
            self.error_flags |= ErrorFlags::DATA_VALUE;
        }

        let (input, data) = take(self.data_length() - 1)(input)?;
        self.data = Data::Read(Read::Response(data.to_vec()));
        Ok(input)
    }

    //                             Num Bytes       Byte Placement
    // FunctionCode::RdWrMultRegs:
    //     Read Address:           2               (0,1)
    //     Read Quantity:          2               (2,3)
    //     <Multiple writes>
    // FunctionCode::MaskWrReg:
    //     Starting Address:       2               (0,1)
    //     And_mask:               2               (2,3)
    //     Or_mask:                2               (4,5)
    // Single write:
    //     Starting Address:       2               (0,1)
    //     Data:                   2               (2,3)
    // Multiple writes:
    //     Starting Address:       2               (0,1)
    //     Quantity of Regs:       2               (2,3)
    //     Byte Count:             1               (4)
    //     Data:                   Count           (5 to (Count + 5))
    //
    // Clippy wants us to factor out the first be_u16 call but we would lose
    // meaning in the variable name.
    fn parse_write_request<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, address) = be_u16(input)?;

        if self.access_type.contains(AccessType::SINGLE) {
            let (input, data) = be_u16(input)?;

            if self.access_type.contains(AccessType::COILS) && data != 0x0000 && data != 0xff00 {
                self.error_flags |= ErrorFlags::DATA_VALUE;
            }

            self.data = Data::Write(Write::Other { address, data });
            Ok(input)
        } else if self.access_type.contains(AccessType::MULTIPLE) {
            let (input, quantity) = be_u16(input)?;
            let (input, count) = be_u8(input)?;

            let mut offset = 7;
            if self.function.code == FunctionCode::RdWrMultRegs {
                offset += 4; // Add 4 bytes for the read section of the request
            }

            if quantity == 0 || self.length - offset != count.into() {
                self.error_flags |= ErrorFlags::DATA_LENGTH;
            }

            if self.access_type.intersects(AccessType::BIT_ACCESS_MASK) {
                if quantity > MAX_QUANTITY_BIT_ACCESS
                    || u16::from(count) != (quantity / 8) + u16::from(quantity % 8 != 0)
                {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }
            } else if quantity > MAX_QUANTITY_WORD_ACCESS
                || u32::from(count) != 2 * u32::from(quantity)
            {
                self.error_flags |= ErrorFlags::DATA_VALUE;
            }

            let (input, data) = take(self.length - offset)(input)?;

            self.data = match &self.data {
                Data::Read(read) => Data::ReadWrite {
                    read: read.clone(),
                    write: Write::MultReq {
                        address,
                        quantity,
                        data: data.to_vec(),
                    },
                },
                _ => Data::Write(Write::MultReq {
                    address,
                    quantity,
                    data: data.to_vec(),
                }),
            };
            Ok(input)
        } else {
            let (input, and_mask) = be_u16(input)?;
            let (input, or_mask) = be_u16(input)?;

            self.data = Data::Write(Write::Mask {
                address,
                and_mask,
                or_mask,
            });
            Ok(input)
        }
    }

    //                             Num Bytes   Byte Placement
    // FunctionCode::MaskWrReg:
    //     Starting Address:       2           (0,1)
    //     And_mask:               2           (2,3)
    //     Or_mask:                2           (4,5)
    // Single write:
    //     Starting Address:       2           (0,1)
    //     Data:                   2           (2,3)
    // Multiple writes:
    //     Starting Address:       2           (0,1)
    //     Quantity of Regs:       2           (2,3)
    //
    // Clippy wants us to factor out the first be_u16 call but we would lose
    // meaning in the variable name.
    fn parse_write_response<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, address) = be_u16(input)?;

        if self.access_type.contains(AccessType::SINGLE) {
            let (input, data) = be_u16(input)?;
            self.data = Data::Write(Write::Other { address, data });
            Ok(input)
        } else if self.access_type.contains(AccessType::MULTIPLE) {
            let (input, quantity) = be_u16(input)?;
            if quantity == 0 {
                self.error_flags |= ErrorFlags::DATA_VALUE;
            }

            if self.access_type.intersects(AccessType::BIT_ACCESS_MASK) {
                if quantity > MAX_QUANTITY_WORD_ACCESS {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }
            } else if quantity > MAX_QUANTITY_BIT_ACCESS {
                self.error_flags |= ErrorFlags::DATA_VALUE;
            }

            self.data = Data::Write(Write::Other {
                address,
                data: quantity,
            });
            Ok(input)
        } else {
            let (input, and_mask) = be_u16(input)?;
            let (input, or_mask) = be_u16(input)?;

            self.data = Data::Write(Write::Mask {
                address,
                and_mask,
                or_mask,
            });
            Ok(input)
        }
    }

    fn parse_request<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        match self.function.code {
            FunctionCode::Diagnostic => {
                if self.data_length() != 4 {
                    self.error_flags |= ErrorFlags::DATA_LENGTH;
                }

                let input = self.parse_diagnostic(input)?;
                if let Data::Diagnostic { func, data } = &self.data {
                    if data.len() == 2 {
                        match func.code {
                            DiagnosticSubfunction::RetQueryData
                            | DiagnosticSubfunction::ForceListenOnlyMode
                            | DiagnosticSubfunction::Reserved => {}
                            DiagnosticSubfunction::RestartCommOpt => {
                                if data[1] != 0x00 || (data[0] != 0x00 && data[0] != 0xff) {
                                    self.error_flags |= ErrorFlags::DATA_VALUE;
                                }
                            }
                            DiagnosticSubfunction::ChangeInputDelimiter => {
                                if data[1] != 0x00 {
                                    self.error_flags |= ErrorFlags::DATA_VALUE;
                                }
                            }
                            _ => {
                                if data[0] != 0x00 || data[1] != 0x00 {
                                    self.error_flags |= ErrorFlags::DATA_VALUE;
                                }
                            }
                        }
                    }
                }

                return Ok(input);
            }
            FunctionCode::MEI => return self.parse_mei(input),
            FunctionCode::RdFileRec | FunctionCode::WrFileRec if self.data_length() == 0 => {
                self.error_flags |= ErrorFlags::DATA_LENGTH
            }
            FunctionCode::RdExcStatus
            | FunctionCode::GetCommEventCtr
            | FunctionCode::GetCommEventLog
            | FunctionCode::ReportServerID
                if self.data_length() > 0 =>
            {
                self.error_flags |= ErrorFlags::DATA_LENGTH
            }
            FunctionCode::RdFIFOQueue if self.data_length() != 2 => {
                self.error_flags |= ErrorFlags::DATA_LENGTH
            }
            _ => {
                if self.function.raw == 0 || self.function.raw >= ERROR_MASK {
                    self.error_flags |= ErrorFlags::FUNC_CODE;
                }

                if self.access_type.intersects(AccessType::READ) {
                    let input = self.parse_read_request(input)?;

                    if self.access_type.intersects(AccessType::WRITE) {
                        return self.parse_write_request(input);
                    }

                    return Ok(input);
                }

                if self.access_type.intersects(AccessType::WRITE) {
                    return self.parse_write_request(input);
                }
            }
        }

        self.parse_bytevec(input)
    }

    fn parse_response<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        match self.function.code {
            _ if self.function.raw >= ERROR_MASK => return self.parse_exception(input),
            FunctionCode::Diagnostic => return self.parse_diagnostic(input),
            FunctionCode::MEI => return self.parse_mei(input),
            FunctionCode::RdExcStatus if self.data_length() != 1 => {
                self.error_flags |= ErrorFlags::DATA_LENGTH
            }
            FunctionCode::GetCommEventCtr if self.data_length() != 4 => {
                self.error_flags |= ErrorFlags::DATA_LENGTH
            }
            _ => {
                if self.access_type.intersects(AccessType::READ) {
                    return self.parse_read_response(input);
                }

                if self.access_type.intersects(AccessType::WRITE) {
                    return self.parse_write_response(input);
                }
            }
        }

        self.parse_bytevec(input)
    }

    fn parse_unknown<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        match self.function.code {
            _ if self.function.raw >= ERROR_MASK => self.parse_exception(input),
            FunctionCode::Diagnostic => self.parse_diagnostic(input),
            FunctionCode::MEI => self.parse_mei(input),
            _ => self.parse_bytevec(input),
        }
    }

    /// Matches this message with another. Used to validate requests with responses.
    pub fn matches(&mut self, other: &Message) -> bool {
        if self.transaction_id != other.transaction_id
            || self.unit_id != other.unit_id
            || self.function.code != other.function.code
            || self.access_type != other.access_type
        {
            return false;
        }

        // This isn't a known function, no validation can be done
        if self.category != CodeCategory::PUBLIC_ASSIGNED {
            return true;
        }

        // If there was an exception, don't bother trying to validate
        // Since we don't know which side is the response, both are checked
        // (self.data checked in the match right below)
        if let Data::Exception(_) = &other.data {
            return true;
        }

        match (&self.data, &other.data) {
            (Data::Exception(_), _) => true,
            (Data::ByteVec(_), Data::ByteVec(_)) => true,
            (Data::ByteVec(_), _) => self.error_flags.intersects(ErrorFlags::DATA_LENGTH),
            (_, Data::ByteVec(_)) => other.error_flags.intersects(ErrorFlags::DATA_LENGTH),
            (
                Data::Read(Read::Response(data)),
                Data::Read(Read::Request {
                    address: _,
                    quantity,
                }),
            ) => {
                let other_count = usize::from(*quantity);

                if data.len() != (other_count / 8) + usize::from((other_count % 8) != 0) {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::Read(Read::Response(data)),
                Data::ReadWrite {
                    read:
                        Read::Request {
                            address: _,
                            quantity,
                        },
                    write: _,
                },
            ) => {
                if data.len() != 2 * usize::from(*quantity) {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::Read(Read::Request {
                    address: _,
                    quantity,
                }),
                Data::Read(Read::Response(data)),
            ) => {
                let count = usize::from(*quantity);

                if data.len() != (count / 8) + usize::from((count % 8) != 0) {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::ReadWrite {
                    read:
                        Read::Request {
                            address: _,
                            quantity,
                        },
                    write: _,
                },
                Data::Read(Read::Response(data)),
            ) => {
                if data.len() != 2 * usize::from(*quantity) {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::Write(Write::Other {
                    address: addr,
                    data,
                }),
                Data::Write(other_write),
            ) => match &other_write {
                Write::Other {
                    address: other_addr,
                    data: other_data,
                } => {
                    if addr != other_addr || data != other_data {
                        self.error_flags |= ErrorFlags::DATA_VALUE;
                    }

                    true
                }
                Write::MultReq {
                    address: other_addr,
                    quantity: other_quantity,
                    data: _,
                } => {
                    if addr != other_addr || data != other_quantity {
                        self.error_flags |= ErrorFlags::DATA_VALUE;
                    }

                    true
                }
                _ => false,
            },
            (
                Data::Write(Write::MultReq {
                    address: addr,
                    quantity,
                    data: _,
                }),
                Data::Write(Write::Other {
                    address: other_addr,
                    data: other_data,
                }),
            ) => {
                if addr != other_addr || quantity != other_data {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::Write(Write::Mask {
                    address: addr,
                    and_mask: and,
                    or_mask: or,
                }),
                Data::Write(Write::Mask {
                    address: other_addr,
                    and_mask: other_and,
                    or_mask: other_or,
                }),
            ) => {
                if addr != other_addr || and != other_and || or != other_or {
                    self.error_flags |= ErrorFlags::DATA_VALUE;
                }

                true
            }
            (
                Data::Diagnostic { func, data: _ },
                Data::Diagnostic {
                    func: other_func,
                    data: _,
                },
            ) => func == other_func,
            (
                Data::MEI { mei_type, data: _ },
                Data::MEI {
                    mei_type: other_mei,
                    data: _,
                },
            ) => mei_type == other_mei,
            _ => false,
        }
    }

    /// Gets the register/coil/input value at the given address, if it has been
    /// modified in the transaction. Returns the value as Some(u16) if it is found,
    /// otherwise returns None. The address passed in must be offset by 1 to reflect
    /// the actual coil/register and not the address found in the PDU. See the
    /// [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
    /// for more information on addresses.
    pub fn get_write_value_at_address(&self, address: u16) -> Option<u16> {
        // Compare the given address with the transaction's address to ensure it is covered
        if let Some(range) = self.get_address_range() {
            if !range.contains(&address) {
                return None;
            }
        }

        if self.access_type.contains(AccessType::SINGLE) {
            // The only functions with AccessType::SINGLE are write functions, limiting the
            // data variant to Write::Other
            let data = if let Data::Write(Write::Other { address: _, data }) = &self.data {
                *data
            } else {
                return None;
            };

            if self.access_type.contains(AccessType::COILS) {
                Some((data != 0) as u16)
            } else {
                Some(data)
            }
        } else if self.access_type.contains(AccessType::MULTIPLE) {
            let (start, data) = match &self.data {
                Data::Write(Write::MultReq {
                    address,
                    quantity: _,
                    data,
                }) => (address, data),
                Data::ReadWrite {
                    read: _,
                    write:
                        Write::MultReq {
                            address,
                            quantity: _,
                            data,
                        },
                } => (address, data),
                _ => return None,
            };

            if *start == std::u16::MAX || *start >= address {
                return None;
            }

            // Multiply by two because each register value is 2 bytes
            let mut offset = (address - (start + 1)) as usize * 2;

            // In case of Coils, offset is in bit (convert to byte)
            if self.access_type.contains(AccessType::COILS) {
                offset >>= 3;
            }

            let mut value =
                if let (Some(val1), Some(val2)) = (data.get(offset), data.get(offset + 1)) {
                    ((*val1 as u16) << 8) | *val2 as u16
                } else {
                    return None;
                };

            if self.access_type.contains(AccessType::COILS) {
                value = (value >> ((address - (start + 1)) & 0x7)) & 0x1;
            }

            Some(value)
        } else {
            None
        }
    }

    /// Gets the address and quantity in the read/write data. If the data does not
    /// match and they can't be found, None is returned.
    /// The range returned is offset by 1 to account to reflect the coils/registers
    /// that start at 1 instead of in the PDU numbers where they start at 0.
    /// More details can be found in the [protocol reference](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf)
    pub fn get_address_range(&self) -> Option<RangeInclusive<u16>> {
        match &self.data {
            Data::Write(Write::Other { address, data: _ })
            | Data::Write(Write::Mask {
                address,
                and_mask: _,
                or_mask: _,
            }) => Some((address + 1)..=(address + 1)),
            Data::Read(Read::Request { address, quantity })
            | Data::Write(Write::MultReq {
                address,
                quantity,
                data: _,
            })
            | Data::ReadWrite {
                read: _,
                write:
                    Write::MultReq {
                        address,
                        quantity,
                        data: _,
                    },
            } => {
                if *quantity > 0 && *quantity <= std::u16::MAX - address {
                    Some((address + 1)..=(address + quantity))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Protocol<'_> for Modbus {
    type Message = Message;

    fn name() -> &'static str {
        "modbus"
    }
}

impl<'a> Probe<'a> for Modbus {
    fn probe(&self, input: &'a [u8], direction: Direction) -> Status {
        match self.parse(input, direction) {
            Ok((_, Some(msg))) => {
                if msg.error_flags == ErrorFlags::none()
                    && (!self.probe_strict || msg.function.code != FunctionCode::Unknown)
                {
                    Status::Recognized
                } else {
                    Status::Unrecognized
                }
            }
            Ok((_, _)) => Status::Recognized,
            Err(Error {
                kind: ErrorKind::Incomplete(_),
            }) => Status::Incomplete,
            Err(_) => Status::Unrecognized,
        }
    }
}

impl<'a> Parse<'a> for Modbus {
    fn parse(
        &self,
        input: &'a [u8],
        direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (input, transaction_id) = be_u16(input)?;
        let (input, protocol_id) = be_u16(input)?;
        let mut err_flags = ErrorFlags::none();
        if protocol_id != 0 {
            err_flags |= ErrorFlags::PROTO_ID;
        }

        let (input, length) = be_u16(input)?;

        let mut message = Message {
            transaction_id,
            protocol_id,
            length,
            unit_id: 0,
            function: Function::new(0),
            access_type: AccessType::none(),
            category: CodeCategory::none(),
            data: Data::Empty,
            error_flags: err_flags,
        };

        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            message.error_flags |= ErrorFlags::DATA_LENGTH;
            if input.len() > usize::from(length) {
                return Ok((&input[usize::from(length)..input.len()], Some(message)));
            } else {
                return Ok((&[], Some(message)));
            }
        }

        let (input, data) = take(length)(input)?;
        let (data, unit_id) = be_u8(data)?;
        let (data, raw_func) = be_u8(data)?;
        message.unit_id = unit_id;
        message.function = Function::new(raw_func);
        message.access_type = message.function.code.into();

        let result = match direction {
            Direction::ToServer => message.parse_request(data),
            Direction::ToClient => message.parse_response(data),
            Direction::Unknown => message.parse_unknown(data),
        };
        match result {
            Ok(rest) => {
                if !rest.is_empty() {
                    message.error_flags |= ErrorFlags::DATA_LENGTH;
                }
            }
            Err(Error {
                kind: ErrorKind::Incomplete(_),
            }) => {
                message.error_flags |= ErrorFlags::DATA_LENGTH;
                if message.data == Data::Empty {
                    message.data = Data::ByteVec(data.to_vec());
                }
            }
            Err(err) => return Err(err),
        }

        message.category = Flags::from(&message);

        Ok((input, Some(message)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error::{Error, Result};
    use sawp::probe::Status;
    use std::str::FromStr;

    #[test]
    fn test_name() {
        assert_eq!(Modbus::name(), "modbus");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error::incomplete_needed(2))),
        case::hello_world(
            b"hello world",
            Ok((0, Some(Message{
                transaction_id: 26725,
                protocol_id: 27756,
                length: 28448,
                unit_id: 0,
                function: Function { raw: 0, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::PROTO_ID | ErrorFlags::DATA_LENGTH,
            })))
        ),
        case::diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Force Listen Only Mode (4)
                0x00, 0x04,
                // Data: 0000
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 4, code: DiagnosticSubfunction::ForceListenOnlyMode }, data: vec![0x00, 0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic_missing_subfunc(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::diagnostic_reserved_1(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Reserved (22)
                0x00, 0x16
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::RESERVED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 22, code: DiagnosticSubfunction::Reserved }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic_reserved_2(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Reserved (5)
                0x00, 0x05
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::RESERVED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 5, code: DiagnosticSubfunction::Reserved }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic_reserved_3(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Reserved (9)
                0x00, 0x09
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::RESERVED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 9, code: DiagnosticSubfunction::Reserved }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::gateway_exception(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 8
                0x08,
                // Function Code: Diagnostics (8) -- Exception
                0x88,
                // Exception Code: Gateway target device failed to respond (11)
                0x0b
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 8,
                function: Function { raw: 136, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Exception(Exception { raw: 11, code: ExceptionCode::GatewayTargetFailToResp }),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::illegal_data_addr(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 8
                0x01,
                // Function Code: Read Coils (1) -- Exception
                0x81,
                // Exception Code: Illegal Data Address (2)
                0x02
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 129, code: FunctionCode::RdCoils },
                access_type: AccessType::READ | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Exception(Exception { raw: 2, code: ExceptionCode::IllegalDataAddr }),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::exception_unknown(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 8
                0x08,
                // Function Code: Unknown (228) -- Exception
                0xe4,
                // Exception Code: Unknown (12)
                0x0c
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 8,
                function: Function { raw: 228, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Exception(Exception { raw: 12, code: ExceptionCode::Unknown }),
                error_flags: ErrorFlags::EXC_CODE.into(),
            })))
        ),
        case::exception_missing_code(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 8
                0x08,
                // Function Code: Diagnostics (8) -- Exception
                0x88
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 2,
                unit_id: 8,
                function: Function { raw: 136, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::ByteVec(Vec::new()),
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::exception_with_extra(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 8
                0x08,
                // Function Code: Diagnostics (8) -- Exception
                0x88,
                // Exception Code: Gateway target device failed to respond (11)
                0x0b,
                // Extra: 00
                0x00
            ],
            Ok((1, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 8,
                function: Function { raw: 136, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Exception(Exception { raw: 11, code: ExceptionCode::GatewayTargetFailToResp }),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::exception_invalid_length(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 4
                0x00, 0x04,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 8
                0x08,
                // Function Code: Diagnostics (8) -- Exception
                0x88,
                // Exception Code: Gateway target device failed to respond (11)
                0x0b
            ],
            Ok((1, Some(Message{
                transaction_id: 0,
                protocol_id: 4,
                length: 2,
                unit_id: 8,
                function: Function { raw: 136, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::ByteVec([].to_vec()),
                error_flags: ErrorFlags::PROTO_ID | ErrorFlags::DATA_LENGTH,
            })))
        ),
        case::server_id(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Report Server ID (17)
                0x11
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 17, code: FunctionCode::ReportServerID },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::server_id_with_extra(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Report Server ID (17)
                0x11,
                // Extra: 05 06 07
                0x05, 0x06, 0x07
            ],
            Ok((3, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 17, code: FunctionCode::ReportServerID },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::invalid_length(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 1
                0x00, 0x01,
                // Unit ID: 1
                0x01,
                // Function Code: Report Server ID (17)
                0x11
            ],
            Ok((1, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 1,
                unit_id: 0,
                function: Function { raw: 0, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::unknown_func(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Unknown (100)
                0x64
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 100, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::USER_DEFINED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::unknown_func_with_extra(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Unknown (100)
                0x64,
                // Extra: 0000
                0x00, 0x00
            ],
            Ok((2, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 100, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::USER_DEFINED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_gen_ref(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_gen_ref_with_extra(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d,
                // Extra: 00
                0x00
            ],
            Ok((1, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_gen_ref_with_data(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d,
                // Data: 00
                0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 4,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_invalid_length(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d,
                // Data: 00
                0x00
            ],
            Ok((2, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::mei_missing_bytes(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 5
                0x00, 0x05,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d,
                // Data: 00
                0x00
            ],
            Err(Error::incomplete_needed(1))
        ),
        case::mei_dev_id(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: Read Device ID (14)
                0x0e,
                // Data: 00
                0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 4,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 14, code: MEIType::RdDevId }, data: vec![0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_unknown(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: Unknown (15)
                0x0f
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::RESERVED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 15, code: MEIType::Unknown }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::zero_length(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 0
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 0,
                unit_id: 0,
                function: Function { raw: 0, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::zero_length(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 0
                0x00, 0x00,
                // Extra: 00 00 00 00
                0x00, 0x00, 0x00, 0x00
            ],
            Ok((4, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 0,
                unit_id: 0,
                function: Function { raw: 0, code: FunctionCode::Unknown },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::missing_bytes(
            &[
                // Transaction ID: 0
                0x00, 0x00,
            ],
            Err(Error::incomplete_needed(2))
        ),
    )]
    fn test_parse(input: &[u8], expected: Result<(usize, Option<<Modbus as Protocol>::Message>)>) {
        let modbus = Modbus::default();
        assert_eq!(
            modbus
                .parse(input, Direction::Unknown)
                .map(|(left, msg)| (left.len(), msg)),
            expected
        );
    }

    #[rstest(
        input,
        expected,
        case::read_coils(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Read Coils (1)
                0x01,
                // Start Address: 0
                0x00, 0x00,
                // Quantity: 1
                0x00, 0x01
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 1, code: FunctionCode::RdCoils },
                access_type: AccessType::READ | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read (
                    Read::Request {
                        address: 0x0000,
                        quantity: 0x0001
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::read_discrete_inputs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Read Discrete Inputs (2)
                0x02,
                // Start Address: 0
                0x00, 0x01,
                // Quantity: 0
                0x00, 0x00
            ],
            Ok((0, Some(Message {
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 2, code: FunctionCode::RdDiscreteInputs },
                access_type: AccessType::READ | AccessType::DISCRETES,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Request {
                    address: 1,
                    quantity: 0
                }),
                error_flags: ErrorFlags::DATA_VALUE.into(),
            })))
        ),
        case::read_input_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Read Input Registers (4)
                0x04,
                // Start Address: 0
                0x00, 0x01,
                // Quantity
                0xFF, 0xFF
            ],
            Ok((0, Some(Message {
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 4, code: FunctionCode::RdInputRegs },
                access_type: AccessType::READ | AccessType::INPUT,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Request {
                    address: 1,
                    quantity: 65535
                }),
                error_flags: ErrorFlags::DATA_VALUE.into(),
            })))
        ),
        case::read_exception_status(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Read Exception Status (7)
                0x07,
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
                function: Function { raw: 7, code: FunctionCode::RdExcStatus },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::read_holding_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Read Holding Registers (3)
                0x03,
                // Start Address: 5
                0x00, 0x05,
                // Quantity: 2
                0x00, 0x02
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 3, code: FunctionCode::RdHoldRegs },
                access_type: AccessType::READ | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read (
                    Read::Request {
                        address: 0x0005,
                        quantity: 0x0002
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::write_single_coil(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Write Single Coil (5)
                0x05,
                // Start Address: 2
                0x00, 0x02,
                // Value: 0
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::write_mult_coils(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 11
                0x00, 0x09,
                // Unit ID: 1
                0x01,
                // Function Code: Write Multiple Coils (15)
                0x0f,
                // Start Address: 19
                0x00, 0x13,
                // Quantity: 15
                0x00, 0x0a,
                // Byte Count: 2
                0x02,
                // Value
                0xcd, 0x01
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 9,
                unit_id: 1,
                function: Function { raw: 15, code: FunctionCode::WrMultCoils },
                access_type: AccessType::COILS | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0013,
                        quantity: 0x000a,
                        data: vec![0xcd, 0x01]
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::write_mult_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 11
                0x00, 0x0b,
                // Unit ID: 1
                0x01,
                // Function Code: Write Multiple Registers (16)
                0x10,
                // Start Address: 3
                0x00, 0x03,
                // Quantity: 2
                0x00, 0x02,
                // Byte Count: 4
                0x04,
                // Value
                0x0a, 0x0b,
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 11,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0002,
                        data: vec![0x0a, 0x0b, 0x00, 0x00]
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::write_mult_regs_invalid_length(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 9
                0x00, 0x09,
                // Unit ID: 1
                0x01,
                // Function Code: Write Multiple Registers (16)
                0x10,
                // Start Address: 3
                0x00, 0x03,
                // Quantity: 2
                0x00, 0x02,
                // Byte Count: 4
                0x04,
                // Value
                0x0a, 0x0b,
                0x00, 0x00
            ],
            Ok((2, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 9,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0002,
                        data: vec![0x0a, 0x0b]
                    }
                ),
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::read_write_mult_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 13
                0x00, 0x0d,
                // Unit ID: 1
                0x01,
                // Function Code: Read/Write Multiple Registers (23)
                0x17,
                // Read Address: 1
                0x00, 0x01,
                // Read Quantity: 2
                0x00, 0x02,
                // Write Address: 3
                0x00, 0x03,
                // Write Quantity: 1
                0x00, 0x01,
                // Write Byte Count: 2
                0x02,
                // Write Value
                0x05, 0x06,
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 13,
                unit_id: 1,
                function: Function { raw: 23, code: FunctionCode::RdWrMultRegs },
                access_type: AccessType::READ | AccessType::WRITE_MULTIPLE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ReadWrite {
                    read: Read::Request {
                        address: 0x0001,
                        quantity: 0x0002
                    },
                    write: Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0001,
                        data: vec![0x05, 0x06]
                    }
                },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mask_write_reg(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 8
                0x00, 0x08,
                // Unit ID: 1
                0x01,
                // Function Code: Mask Write Register (22)
                0x16,
                // Start Address: 1
                0x00, 0x01,
                // And mask: 2
                0x00, 0x02,
                // Or mask: 3
                0x00, 0x03,
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 8,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Mask {
                        address: 0x0001,
                        and_mask: 0x0002,
                        or_mask: 0x0003
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mask_write_reg_invalid_length(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Mask Write Register (22)
                0x16,
                // Start Address: 1
                0x00, 0x01,
                // And mask: 2
                0x00, 0x02,
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec ([0x00, 0x01, 0x00, 0x02].to_vec()),
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::mask_write_reg_invalid_length_complete(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Mask Write Register (22)
                0x16,
                // Start Address: 1
                0x00, 0x01,
                // And mask: 2
                0x00, 0x02,
                // Or mask: 3
                0x00, 0x03,
            ],
            Ok((2, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec ([0x00, 0x01, 0x00, 0x02].to_vec()),
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::mei_gen_ref(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Force Listen Only Mode (4)
                0x00, 0x04,
                // Data: 0000
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 4, code: DiagnosticSubfunction::ForceListenOnlyMode }, data: vec![0x00, 0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic_invalid_value(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Restart Communications Option (1)
                0x00, 0x01,
                // Data: 0000
                0x01, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 1, code: DiagnosticSubfunction::RestartCommOpt }, data: vec![0x01, 0x00] },
                error_flags: ErrorFlags::DATA_VALUE.into(),
            })))
        ),
        case::diagnostic_missing_subfunc(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::none(),
                data: Data::Empty,
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::diagnostic_reserved(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Reserved (22)
                0x00, 0x16,
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::RESERVED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 22, code: DiagnosticSubfunction::Reserved }, data: vec![0x00, 0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
    )]
    fn test_request(
        input: &[u8],
        expected: Result<(usize, Option<<Modbus as Protocol>::Message>)>,
    ) {
        let modbus = Modbus::default();
        assert_eq!(
            modbus
                .parse(input, sawp::parser::Direction::ToServer)
                .map(|(left, msg)| (left.len(), msg)),
            expected
        );
    }

    #[rstest(
        input,
        expected,
        case::read_coils(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 1
                0x01,
                // Function Code: Read Coils (1)
                0x01,
                // Byte Count: 1
                0x01,
                // Data
                0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 1,
                function: Function { raw: 1, code: FunctionCode::RdCoils },
                access_type: AccessType::READ | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Response(vec![0x00])),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::read_holding_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 7
                0x00, 0x07,
                // Unit ID: 1
                0x01,
                // Function Code: Read Holding Registers (3)
                0x03,
                // Byte Count: 4
                0x04,
                // Data
                0x00, 0x09,
                0x00, 0x18
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 7,
                unit_id: 1,
                function: Function { raw: 3, code: FunctionCode::RdHoldRegs },
                access_type: AccessType::READ | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Response(vec![0x00, 0x09, 0x00, 0x18])),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::read_write_mult_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 5
                0x00, 0x05,
                // Unit ID: 1
                0x01,
                // Function Code: Read/Write Multiple Registers (23)
                0x17,
                // Byte Count: 2
                0x02,
                // Data
                0x0e, 0x0f
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 5,
                unit_id: 1,
                function: Function { raw: 23, code: FunctionCode::RdWrMultRegs },
                access_type: AccessType::READ | AccessType::WRITE_MULTIPLE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Response(vec![0x0e, 0x0f])),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::invalid_read_exception_status(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 4
                0x00, 0x04,
                // Unit ID: 1
                0x01,
                // Function Code: Read Exception Status (7)
                0x07,
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 1,
                function: Function { raw: 7, code: FunctionCode::RdExcStatus },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![0x00, 0x00]),
                error_flags: ErrorFlags::DATA_LENGTH.into(),
            })))
        ),
        case::write_single_coil(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Write Single Coil (5)
                0x05,
                // Start Address: 2
                0x00, 0x02,
                // Value: 0
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write(
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::write_mult_regs(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 1
                0x01,
                // Function Code: Write Multiple Registers (16)
                0x10,
                // Start Address: 3
                0x00, 0x03,
                // Quantity: 4
                0x00, 0x04
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::WRITE_MULTIPLE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write(
                    Write::Other {
                        address: 0x0003,
                        data: 0x0004
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mask_write_reg(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 8
                0x00, 0x08,
                // Unit ID: 1
                0x01,
                // Function Code: Mask Write Register (22)
                0x16,
                // Start Address: 1
                0x00, 0x01,
                // And mask: 2
                0x00, 0x02,
                // Or mask: 3
                0x00, 0x03,
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 8,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Mask {
                        address: 0x0001,
                        and_mask: 0x0002,
                        or_mask: 0x0003
                    }
                ),
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::mei_gen_ref(
            &[
                // Transaction ID: 0
                0x00, 0x00,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 3
                0x00, 0x03,
                // Unit ID: 1
                0x01,
                // Function Code: Encapsulated Interface Transport (43)
                0x2b,
                // MEI type: CAN Open General Reference Request and Response (13)
                0x0d
            ],
            Ok((0, Some(Message{
                transaction_id: 0,
                protocol_id: 0,
                length: 3,
                unit_id: 1,
                function: Function { raw: 43, code: FunctionCode::MEI },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] },
                error_flags: ErrorFlags::none(),
            })))
        ),
        case::diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Force Listen Only Mode (4)
                0x00, 0x04,
                // Data: 0000
                0x00, 0x00
            ],
            Ok((0, Some(Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 3,
                function: Function { raw: 8, code: FunctionCode::Diagnostic },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Diagnostic { func: Diagnostic { raw: 4, code: DiagnosticSubfunction::ForceListenOnlyMode }, data: vec![0x00, 0x00] },
                error_flags: ErrorFlags::none(),
            })))
        ),
    )]
    fn test_response(
        input: &[u8],
        expected: Result<(usize, Option<<Modbus as Protocol>::Message>)>,
    ) {
        let modbus = Modbus::default();
        assert_eq!(
            modbus
                .parse(input, sawp::parser::Direction::ToClient)
                .map(|(left, msg)| (left.len(), msg)),
            expected
        );
    }

    #[rstest(
        req,
        resp,
        expected,
        case::read_coils(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 1, code: FunctionCode::RdCoils },
                access_type: AccessType::READ | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read (
                    Read::Request {
                        address: 0x0000,
                        quantity: 0x0001
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 4,
                unit_id: 1,
                function: Function { raw: 1, code: FunctionCode::RdCoils },
                access_type: AccessType::READ | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read(Read::Response(vec![0x00])),
                error_flags: ErrorFlags::none(),
            },
            true
        ),
        case::write_single_coil(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write(
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            true
        ),
        case::write_mult_regs(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 11,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0002,
                        data: vec![0x0a, 0x0b, 0x00, 0x00]
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::WRITE_MULTIPLE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write(
                    Write::Other {
                        address: 0x0003,
                        data: 0x0004
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            true
        ),
        case::read_file_record(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
                error_flags: ErrorFlags::none(),
            },
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![0x07, 0x07, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00]),
                error_flags: ErrorFlags::none(),
            },
            true
        ),
        case::mask_write_reg(
            Message {
                transaction_id: 1,
                protocol_id: 0,
                length: 8,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Mask {
                        address: 0x0001,
                        and_mask: 0x0002,
                        or_mask: 0x0003
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Message {
                transaction_id: 1,
                protocol_id: 0,
                length: 8,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Mask {
                        address: 0x0002,
                        and_mask: 0x0002,
                        or_mask: 0x0003
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            true
        ),
        case::unit_mismatch(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 2,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            },
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![]),
                error_flags: ErrorFlags::none(),
            },
            false
        ),
    )]
    fn test_matching(mut req: Message, mut resp: Message, expected: bool) {
        assert_eq!(req.matches(&resp), expected);
        assert_eq!(resp.matches(&req), expected);
    }

    #[rstest(
        msg,
        addr,
        expected,
        case::write_single_coil(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            3,
            Some(0)
        ),
        case::write_mult_regs(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 11,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0002,
                        data: vec![0x0a, 0x0b, 0x00, 0x00]
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            4,
            Some(0x0a0b)
        ),
        case::read_file_record(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
                error_flags: ErrorFlags::none(),
            },
            0,
            None
        )
    )]
    fn test_write_value_at_address(msg: Message, addr: u16, expected: Option<u16>) {
        assert_eq!(msg.get_write_value_at_address(addr), expected);
    }

    #[rstest(
        msg,
        expected,
        case::write_single_coil(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 6,
                unit_id: 1,
                function: Function { raw: 5, code: FunctionCode::WrSingleCoil },
                access_type: AccessType::WRITE_SINGLE | AccessType::COILS,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Other {
                        address: 0x0002,
                        data: 0x0000
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Some(3..=3)
        ),
        case::write_mult_regs(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 11,
                unit_id: 1,
                function: Function { raw: 16, code: FunctionCode::WrMultRegs },
                access_type: AccessType::HOLDING | AccessType::WRITE_MULTIPLE,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::MultReq {
                        address: 0x0003,
                        quantity: 0x0002,
                        data: vec![0x0a, 0x0b, 0x00, 0x00]
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Some(4..=5)
        ),
        case::mask_write_reg(
            Message {
                transaction_id: 1,
                protocol_id: 0,
                length: 8,
                unit_id: 1,
                function: Function { raw: 22, code: FunctionCode::MaskWrReg },
                access_type: AccessType::WRITE | AccessType::HOLDING,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Write (
                    Write::Mask {
                        address: 0x0001,
                        and_mask: 0x0002,
                        or_mask: 0x0003
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            Some(2..=2)
        ),
        case::read_file_record(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 20, code: FunctionCode::RdFileRec },
                access_type: AccessType::none(),
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::ByteVec(vec![0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
                error_flags: ErrorFlags::none(),
            },
            None
        ),
        // test with overflow of address + quantity
        case::read_file_record(
            Message{
                transaction_id: 1,
                protocol_id: 0,
                length: 10,
                unit_id: 1,
                function: Function { raw: 1, code: FunctionCode::RdCoils },
                access_type: AccessType::COILS | AccessType::READ,
                category: CodeCategory::PUBLIC_ASSIGNED.into(),
                data: Data::Read (
                    Read::Request {
                        address: 0xA000,
                        quantity: 0xC000,
                    }
                ),
                error_flags: ErrorFlags::none(),
            },
            None
        )
    )]
    fn test_address_range(msg: Message, expected: Option<RangeInclusive<u16>>) {
        assert_eq!(msg.get_address_range(), expected);
    }

    #[rstest(
        input,
        probe_strict,
        expected,
        case::empty(b"", false, Status::Incomplete),
        case::hello_world(b"hello world", false, Status::Unrecognized),
        case::diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Force Listen Only Mode (4)
                0x00, 0x04,
                // Data: 0000
                0x00, 0x00
            ],
            false,
            Status::Recognized
        ),
        case::invalid_diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08
            ],
            false,
            Status::Unrecognized
        ),
        case::unknown_func(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Unknown (100)
                0x64
            ],
            false,
            Status::Recognized
        ),
        case::strict_diagnostic(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 6
                0x00, 0x06,
                // Unit ID: 3
                0x03,
                // Function Code: Diagnostics (8)
                0x08,
                // Diagnostic Code: Force Listen Only Mode (4)
                0x00, 0x04,
                // Data: 0000
                0x00, 0x00
            ],
            true,
            Status::Recognized
        ),
        case::strict_unknown_func(
            &[
                // Transaction ID: 1
                0x00, 0x01,
                // Protocol ID: 0
                0x00, 0x00,
                // Length: 2
                0x00, 0x02,
                // Unit ID: 1
                0x01,
                // Function Code: Unknown (100)
                0x64
            ],
            true,
            Status::Unrecognized
        ),
    )]
    fn test_probe(input: &[u8], probe_strict: bool, expected: Status) {
        let modbus = Modbus { probe_strict };
        assert_eq!(modbus.probe(input, Direction::Unknown), expected);
    }

    #[test]
    fn test_categories() {
        assert_eq!(CodeCategory::PUBLIC_UNASSIGNED, CodeCategory::from_raw(99));
        assert_eq!(CodeCategory::USER_DEFINED, CodeCategory::from_raw(100));
        assert_eq!(CodeCategory::RESERVED, CodeCategory::from_raw(126));
    }

    #[test]
    fn test_access_type() {
        // make sure complex access types didn't get typoed
        assert_eq!(
            AccessType::DISCRETES | AccessType::COILS,
            AccessType::BIT_ACCESS_MASK
        );
        assert_eq!(
            AccessType::DISCRETES | AccessType::COILS | AccessType::INPUT | AccessType::HOLDING,
            AccessType::FUNC_MASK
        );
        assert_eq!(
            AccessType::WRITE | AccessType::SINGLE,
            AccessType::WRITE_SINGLE
        );
        assert_eq!(
            AccessType::WRITE | AccessType::MULTIPLE,
            AccessType::WRITE_MULTIPLE
        );
    }

    #[test]
    fn test_printing() {
        assert_eq!(
            "PUBLIC_ASSIGNED | RESERVED",
            (CodeCategory::PUBLIC_ASSIGNED | CodeCategory::RESERVED).to_string()
        );
        assert_eq!("NONE", CodeCategory::none().to_string());
        assert_eq!(
            "READ | COILS",
            (AccessType::READ | AccessType::COILS).to_string()
        );
        assert_eq!(
            "WRITE | MULTIPLE | WRITE_MULTIPLE",
            AccessType::WRITE_MULTIPLE.to_string()
        );
        assert_eq!(AccessType::from_str("write"), Ok(AccessType::WRITE));
        assert_eq!(AccessType::from_str("writ"), Err(()));
        assert_eq!("RdCoils", FunctionCode::RdCoils.to_string());
        assert_eq!(
            "RetQueryData",
            DiagnosticSubfunction::RetQueryData.to_string()
        );
        assert_eq!("Unknown", MEIType::Unknown.to_string());
        assert_eq!(
            "IllegalFunction",
            ExceptionCode::IllegalFunction.to_string()
        );
    }
}
