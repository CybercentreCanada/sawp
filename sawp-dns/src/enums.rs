use num_enum::TryFromPrimitive;

use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum RecordType {
    /// Address record
    A = 1,
    /// Name server record
    NS = 2,
    /// Obsolete
    MD = 3,
    /// Obsolete
    MF = 4,
    /// Canonical name record
    CNAME = 5,
    /// Start of authority record
    SOA = 6,
    /// Unlikely to be adopted. See https://tools.ietf.org/html/rfc2505
    MB = 7,
    /// Unlikely to be adopted. See https://tools.ietf.org/html/rfc2505
    MG = 8,
    /// Unlikely to be adopted. See https://tools.ietf.org/html/rfc2505
    MR = 9,
    /// Obsolete
    NUL = 10,
    /// Not to be relied upon. See https://tools.ietf.org/html/rfc1123
    WKS = 11,
    /// PTR resource record (pointer to a canonical name)
    PTR = 12,
    /// Host information
    HINFO = 13,
    /// Unlikely to be adopted. See https://tools.ietf.org/html/rfc2505
    MINFO = 14,
    /// Mail exchange record
    MX = 15,
    /// Text record
    TXT = 16,
    /// Responsible person
    RP = 17,
    /// AFS database record
    AFSDB = 18,
    /// Maps a domain name to a PSDN address number
    X25 = 19,
    /// Maps a domain name to an ISDN telephone number
    ISDN = 20,
    /// Specifies intermediate host routing to host with the name of the RT-record
    RT = 21,
    /// Maps a domain name to an NSAP address
    NSAP = 22,
    /// Facilitates translation from NSAP address to DNS name
    NSAPPTR = 23,
    /// Signature - obsolete
    SIG = 24,
    /// Key record - obsolete
    KEY = 25,
    /// Pointer to X.400/RFC822 mapping information
    PX = 26,
    /// A more limited early version of LOC
    GPOS = 27,
    /// IPv6 address record
    AAAA = 28,
    /// Location record
    LOC = 29,
    /// Obsolete
    NXT = 30,
    /// Never made it to RFC status. See https://tools.ietf.org/html/draft-ietf-nimrod-dns-00
    EID = 31,
    /// Never made it to RFC status. See https://tools.ietf.org/html/draft-ietf-nimrod-dns-00
    NIMLOC = 32,
    /// Service locator
    SRV = 33,
    /// Defined by the ATM forum committee
    ATMA = 34,
    /// Naming authority pointer
    NAPTR = 35,
    /// Key exchanger record
    KX = 36,
    /// Certificate record
    CERT = 37,
    /// Obsolete
    A6 = 38,
    /// Delegation name record
    DNAME = 39,
    /// Never made it to RFC status. See https://tools.ietf.org/html/draft-eastlake-kitchen-sink
    SINK = 40,
    /// Option (needed to support EDNS)
    OPT = 41,
    /// Address prefix list
    APL = 42,
    /// Delegation signer
    DS = 43,
    /// SSH public key fingerprint
    SSHFP = 44,
    /// IPsec key
    IPSECKEY = 45,
    /// DNSSEC signature
    RRSIG = 46,
    /// Next Secure record
    NSEC = 47,
    /// DNS Key record
    DNSKEY = 48,
    /// DHCP identifier
    DHCID = 49,
    /// Next Secure record version 3
    NSEC3 = 50,
    /// NSEC3 parameters
    NSEC3PARAM = 51,
    /// TLSA certificate association
    TLSA = 52,
    /// S/MIME cert association
    SMIMEA = 53,
    /// Host Identity Protocol
    HIP = 55,
    /// Expired without adoption by IETF
    NINFO = 56,
    /// Expired without adoption by IETF
    RKEY = 57,
    /// Never made it to RFC status. See https://tools.ietf.org/html/draft-wijngaards-dnsop-trust-history-02
    TALINK = 58,
    /// Child DS
    CDS = 59,
    /// Child DNSKEY
    CDNSKEY = 60,
    /// OpenPGP public key record
    OPENPGPKEY = 61,
    /// Child-to-parent synchronization
    CSYNC = 62,
    /// Draft: see https://tools.ietf.org/html/draft-ietf-dnsop-dns-zone-digest-14
    ZONEMD = 63,
    /// Draft: see https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00
    SVCB = 64,
    /// Draft: see https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00
    HTTPS = 65,
    /// Obsolete
    SPF = 99,
    /// IANA reserved
    UINFO = 100,
    /// IANA reserved
    UID = 101,
    /// IANA reserved
    GID = 102,
    /// IANA reserved
    UNSPEC = 103,
    /// Experimental: see https://tools.ietf.org/html/rfc6742
    NID = 104,
    /// Experimental: see https://tools.ietf.org/html/rfc6742
    L32 = 105,
    /// Experimental: see https://tools.ietf.org/html/rfc6742
    L64 = 106,
    /// Experimental: see https://tools.ietf.org/html/rfc6742
    LP = 107,
    /// MAC address (EUI-48)
    EUI48 = 108,
    /// MAC address (EUI-64)
    EUI64 = 109,
    /// Transaction key record
    TKEY = 249,
    /// Transaction signature
    TSIG = 250,
    /// Incremental zone transfer
    IXFR = 251,
    /// Authoritative zone transfer
    AXFR = 252,
    /// Returns MB, MG, MR, or MINFO. Unlikely to be adopted.
    MAILB = 253,
    /// Obsolete
    MAILA = 254,
    /// All cached records
    ANY = 255,
    /// Uniform resource identifier
    URI = 256,
    /// Certification authority authorization
    CAA = 257,
    /// Application visibility and control
    AVC = 258,
    /// Digital object architecture
    DOA = 259,
    /// Automatic multicast tunneling relay
    AMTRELAY = 260,
    /// DNSSEC trust authorities
    TA = 32768,
    /// DNSSEC lookaside validation record
    DLV = 32769,
    UNKNOWN,
}

impl RecordType {
    pub fn from_raw(val: u16) -> Self {
        RecordType::try_from(val).unwrap_or(RecordType::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum RecordClass {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
    UNKNOWN,
}

impl RecordClass {
    pub fn from_raw(val: u16) -> Self {
        RecordClass::try_from(val).unwrap_or(RecordClass::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum OpCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
    DSO = 6,
    UNKNOWN,
}

impl OpCode {
    pub fn from_raw(val: u16) -> Self {
        OpCode::try_from(val).unwrap_or(OpCode::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum ResponseCode {
    /// No error condition.
    NOERROR = 0,
    /// The name server was unable to interpret the query.
    FORMATERROR = 1,
    /// There was a problem with the name server.
    SERVERFAILURE = 2,
    /// The domain name referenced in the query does not exist.
    NAMEERROR = 3,
    /// The name server does not support the requested kind of query.
    NOTIMPLEMENTED = 4,
    /// The name server's policy forbids providing this information.
    REFUSED = 5,
    /// Name exists when it should not.
    YXDOMAIN = 6,
    /// RR set exists when it should not.
    YXRRSET = 7,
    /// RR set that should exist does not.
    NXRRSET = 8,
    /// Server not authoritative for zone or client not authorized.
    NOTAUTH = 9,
    /// Name not in contained zone.
    NOTZONE = 10,
    UNKNOWN,
}

impl ResponseCode {
    pub fn from_raw(val: u16) -> Self {
        ResponseCode::try_from(val).unwrap_or(ResponseCode::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum OptResponseCode {
    /// No error condition.
    NOERROR = 0,
    /// The name server was unable to interpret the query.
    FORMATERROR = 1,
    /// There was a problem with the name server.
    SERVERFAILURE = 2,
    /// The domain name referenced in the query does not exist.
    NAMEERROR = 3,
    /// The name server does not support the requested kind of query.
    NOTIMPLEMENTED = 4,
    /// The name server's policy forbids providing this information.
    REFUSED = 5,
    /// Name exists when it should not.
    YXDOMAIN = 6,
    /// RR set exists when it should not.
    YXRRSET = 7,
    /// RR set that should exist does not.
    NXRRSET = 8,
    /// Server not authoritative for zone or client not authorized.
    NOTAUTH = 9,
    /// Name not in contained zone.
    NOTZONE = 10,
    /// Bad OPT version
    BADVERSION = 16,
    /// Bad/missing server cookie
    BADCOOKIE = 23,
    UNKNOWN,
}

impl OptResponseCode {
    pub fn from_raw(val: u16) -> Self {
        OptResponseCode::try_from(val).unwrap_or(OptResponseCode::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum TSigResponseCode {
    /// No error condition.
    NOERROR = 0,
    /// The name server was unable to interpret the query.
    FORMATERROR = 1,
    /// There was a problem with the name server.
    SERVERFAILURE = 2,
    /// The domain name referenced in the query does not exist.
    NAMEERROR = 3,
    /// The name server does not support the requested kind of query.
    NOTIMPLEMENTED = 4,
    /// The name server's policy forbids providing this information.
    REFUSED = 5,
    /// Name exists when it should not.
    YXDOMAIN = 6,
    /// RR set exists when it should not.
    YXRRSET = 7,
    /// RR set that should exist does not.
    NXRRSET = 8,
    /// Server not authoritative for zone or client not authorized.
    NOTAUTH = 9,
    /// Name not in contained zone.
    NOTZONE = 10,
    /// Bad OPT version
    BADSIGNATURE = 16,
    /// Key not recognized
    BADKEY = 17,
    /// Signature out of time window
    BADTIME = 18,
    /// Bad TKEY mode
    BADMODE = 19,
    /// Duplicate key name
    BADNAME = 20,
    /// Algorithm not supported
    BADALG = 21,
    /// Bad truncation
    BADTRUNC = 22,
    /// Bad/missing server cookie
    BADCOOKIE = 23,
    UNKNOWN,
}

impl TSigResponseCode {
    pub fn from_raw(val: u16) -> Self {
        TSigResponseCode::try_from(val).unwrap_or(TSigResponseCode::UNKNOWN)
    }
}

/// Indicates whether the message is a query or response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QueryResponse {
    Query = 0,
    Response = 1,
}

/// Helper enum for determining where to store parsed answers in the message
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum AnswerType {
    Answer = 0,
    Nameserver = 1,
    Additional = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshfpAlgorithm {
    RESERVED = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    Ed25519 = 4,
    UNKNOWN,
}

impl SshfpAlgorithm {
    pub fn from_raw(val: u8) -> Self {
        SshfpAlgorithm::try_from(val).unwrap_or(SshfpAlgorithm::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshfpFingerprint {
    RESERVED = 0,
    SHA1 = 1,
    SHA256 = 2,
    UNKNOWN,
}

impl SshfpFingerprint {
    pub fn from_raw(val: u8) -> Self {
        SshfpFingerprint::try_from(val).unwrap_or(SshfpFingerprint::UNKNOWN)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum TkeyMode {
    RESERVED = 0,
    ServerAssignment = 1,
    DiffieHelmanExchange = 2,
    GssApiNegotiation = 3,
    ResolverAssignment = 4,
    KeyDeletion = 5,
    UNKNOWN,
}

impl TkeyMode {
    pub fn from_raw(val: u16) -> Self {
        TkeyMode::try_from(val).unwrap_or(TkeyMode::UNKNOWN)
    }
}
