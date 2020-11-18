//! Protocol References:
//!    https://modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
//!    https://modbus.org/docs/PI_MBUS_300.pdf

use sawp::error::{Error, ErrorKind, Result};
use sawp::parser::Parse;
use sawp::protocol::Protocol;

use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u8};

use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::num::NonZeroUsize;

#[derive(Debug, PartialEq)]
pub struct Function {
    pub raw: u8,
    pub code: FunctionCode,
}

impl Function {
    fn new(val: u8) -> Function {
        Function {
            raw: val,
            code: {
                if val >= ERROR_MASK {
                    FunctionCode::try_from(val ^ ERROR_MASK).unwrap_or(FunctionCode::Unknown)
                } else {
                    FunctionCode::try_from(val).unwrap_or(FunctionCode::Unknown)
                }
            },
        }
    }
}

#[derive(Debug, PartialEq, TryFromPrimitive)]
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

#[derive(Debug, PartialEq)]
pub struct Diagnostic {
    pub raw: u16,
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

#[derive(Debug, PartialEq, TryFromPrimitive)]
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

#[derive(Debug, PartialEq)]
pub struct MEI {
    pub raw: u8,
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

#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum MEIType {
    Unknown = 0x00,
    CANOpenGenRefReqResp = 0x0d,
    RdDevId = 0x0e,
}

#[derive(Debug, PartialEq)]
pub struct Exception {
    pub raw: u8,
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

#[derive(Debug, PartialEq, TryFromPrimitive)]
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
const ERROR_MASK: u8 = 0x80;

#[derive(Debug, PartialEq)]
pub enum Data {
    Exception(Exception),
    Diagnostic { func: Diagnostic, data: Vec<u8> },
    MEI { mei_type: MEI, data: Vec<u8> },
    ByteVec(Vec<u8>),
}

#[derive(Debug)]
pub struct Modbus {}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub unit_id: u8,
    pub function_code: Function,
    pub data: Data,
}

impl Protocol<'_> for Modbus {
    type Message = Message;

    fn name() -> &'static str {
        "modbus"
    }
}

impl<'a> Parse<'a> for Modbus {
    fn parse(&self, input: &'a [u8]) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (input, transaction_id) = be_u16(input)?;
        let (input, protocol_id) = be_u16(input)?;
        if protocol_id != 0 {
            return Err(Error::new(ErrorKind::InvalidData));
        }

        let (input, length) = be_u16(input)?;
        if usize::from(length) > input.len() {
            let needed = usize::from(length) - input.len();
            let needed = NonZeroUsize::new(needed)
                .ok_or_else(|| Error::new(ErrorKind::ExpectedNonZero(needed)))?;
            return Err(Error::new(ErrorKind::Incomplete(nom::Needed::Size(needed))));
        }

        let (input, unit_id) = be_u8(input)?;
        let (input, raw_func) = be_u8(input)?;
        let func = Function::new(raw_func);

        match func.code {
            _ if raw_func >= ERROR_MASK => {
                if length < 3 {
                    return Err(Error::new(ErrorKind::InvalidData));
                }

                let (input, exc_code) = be_u8(input)?;
                Ok((
                    input,
                    Some(Message {
                        transaction_id,
                        protocol_id,
                        unit_id,
                        function_code: func,
                        data: Data::Exception(Exception::new(exc_code)),
                    }),
                ))
            }
            FunctionCode::Diagnostic => {
                if length < 4 {
                    return Err(Error::new(ErrorKind::InvalidData));
                }

                let (input, diag_func) = be_u16(input)?;
                let (input, rest) = take(length - 4)(input)?;

                Ok((
                    input,
                    Some(Message {
                        transaction_id,
                        protocol_id,
                        unit_id,
                        function_code: func,
                        data: Data::Diagnostic {
                            func: Diagnostic::new(diag_func),
                            data: rest.to_vec(),
                        },
                    }),
                ))
            }
            FunctionCode::MEI => {
                if length < 3 {
                    return Err(Error::new(ErrorKind::InvalidData));
                }

                let (input, mei) = be_u8(input)?;
                let (input, rest) = take(length - 3)(input)?;
                Ok((
                    input,
                    Some(Message {
                        transaction_id,
                        protocol_id,
                        unit_id,
                        function_code: func,
                        data: Data::MEI {
                            mei_type: MEI::new(mei),
                            data: rest.to_vec(),
                        },
                    }),
                ))
            }
            FunctionCode::Unknown => {
                if length < 2 {
                    return Err(Error::new(ErrorKind::InvalidData));
                }

                let (input, data) = take(length - 2)(input)?;
                Ok((
                    input,
                    Some(Message {
                        transaction_id,
                        protocol_id,
                        unit_id,
                        function_code: func,
                        data: Data::ByteVec(data.to_vec()),
                    }),
                ))
            }
            _ => {
                if length < 2 {
                    return Err(Error::new(ErrorKind::InvalidData));
                }

                let (input, data) = take(length - 2)(input)?;
                Ok((
                    input,
                    Some(Message {
                        transaction_id,
                        protocol_id,
                        unit_id,
                        function_code: func,
                        data: Data::ByteVec(data.to_vec()),
                    }),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error::{Error, ErrorKind, Result};

    #[test]
    fn test_name() {
        assert_eq!(Modbus::name(), "modbus");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error { kind: ErrorKind::Incomplete(nom::Needed::Size(NonZeroUsize::new(2).unwrap())) })),
        case::hello_world(b"hello world", Err(Error { kind: ErrorKind::InvalidData })),
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
                unit_id: 3,
                function_code: Function { raw: 8, code: FunctionCode::Diagnostic },
                data: Data::Diagnostic { func: Diagnostic { raw: 4, code: DiagnosticSubfunction::ForceListenOnlyMode }, data: vec![0x00, 0x00] }
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
            Err(Error { kind: ErrorKind::InvalidData })
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
                unit_id: 3,
                function_code: Function { raw: 8, code: FunctionCode::Diagnostic },
                data: Data::Diagnostic { func: Diagnostic { raw: 22, code: DiagnosticSubfunction::Reserved }, data: vec![] }
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
                unit_id: 3,
                function_code: Function { raw: 8, code: FunctionCode::Diagnostic },
                data: Data::Diagnostic { func: Diagnostic { raw: 5, code: DiagnosticSubfunction::Reserved }, data: vec![] }
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
                unit_id: 3,
                function_code: Function { raw: 8, code: FunctionCode::Diagnostic },
                data: Data::Diagnostic { func: Diagnostic { raw: 9, code: DiagnosticSubfunction::Reserved }, data: vec![] }
            })))
        ),
        case::exception(
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
                unit_id: 8,
                function_code: Function { raw: 136, code: FunctionCode::Diagnostic },
                data: Data::Exception(Exception { raw: 11, code: ExceptionCode::GatewayTargetFailToResp })
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
                unit_id: 8,
                function_code: Function { raw: 228, code: FunctionCode::Unknown },
                data: Data::Exception(Exception { raw: 12, code: ExceptionCode::Unknown })
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
            Err(Error::new(ErrorKind::InvalidData))
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
                unit_id: 8,
                function_code: Function { raw: 136, code: FunctionCode::Diagnostic },
                data: Data::Exception(Exception { raw: 11, code: ExceptionCode::GatewayTargetFailToResp })
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
            Err(Error { kind: ErrorKind::InvalidData })
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
                unit_id: 1,
                function_code: Function { raw: 17, code: FunctionCode::ReportServerID },
                data: Data::ByteVec(vec![])
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
                unit_id: 1,
                function_code: Function { raw: 17, code: FunctionCode::ReportServerID },
                data: Data::ByteVec(vec![])
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
            Err(Error { kind: ErrorKind::InvalidData })
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
                unit_id: 1,
                function_code: Function { raw: 100, code: FunctionCode::Unknown },
                data: Data::ByteVec(vec![])
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
                unit_id: 1,
                function_code: Function { raw: 100, code: FunctionCode::Unknown },
                data: Data::ByteVec(vec![])
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
                unit_id: 1,
                function_code: Function { raw: 43, code: FunctionCode::MEI },
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] }
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
                unit_id: 1,
                function_code: Function { raw: 43, code: FunctionCode::MEI },
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![] }
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
                unit_id: 1,
                function_code: Function { raw: 43, code: FunctionCode::MEI },
                data: Data::MEI{ mei_type: MEI { raw: 13, code: MEIType::CANOpenGenRefReqResp }, data: vec![0x00] }
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
            Err(Error { kind: ErrorKind::InvalidData })
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
            Err(Error { kind: ErrorKind::Incomplete(nom::Needed::Size(NonZeroUsize::new(1).unwrap())) })
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
                unit_id: 1,
                function_code: Function { raw: 43, code: FunctionCode::MEI },
                data: Data::MEI{ mei_type: MEI { raw: 14, code: MEIType::RdDevId }, data: vec![0x00] }
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
                unit_id: 1,
                function_code: Function { raw: 43, code: FunctionCode::MEI },
                data: Data::MEI{ mei_type: MEI { raw: 15, code: MEIType::Unknown }, data: vec![] }
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
            Err(Error { kind: ErrorKind::InvalidData })
        ),
        case::missing_bytes(
            &[
                // Transaction ID: 0
                0x00, 0x00,
            ],
            Err(Error { kind: ErrorKind::Incomplete(nom::Needed::Size(NonZeroUsize::new(2).unwrap())) })
        ),
    )]
    #[test]
    fn test_modbus(input: &[u8], expected: Result<(usize, Option<<Modbus as Protocol>::Message>)>) {
        let modbus = Modbus {};
        assert_eq!(
            modbus.parse(input).map(|(left, msg)| (left.len(), msg)),
            expected
        );
    }
}
