from scapy.fields import BitEnumField,      \
                         BitField,          \
                         ByteField,         \
                         IntField,          \
                         ConditionalField,  \
                         FlagsField,        \
                         LongField,         \
                         XShortField,       \
                         ShortField,        \
                         SignedByteField,   \
                         XBitField,         \
                         XByteField,        \
                         XIntField,         \
                         XStrFixedLenField
from scapy.packet import Packet


class Sync(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol Sync"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x0, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 255),
        FlagsField("flags", 0x0000, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0x9E48),
        XByteField("control", 0x05),
        SignedByteField("logMessageInterval", 0x0F),

        # Sync
        BitField("originTimestamp", 0x000045B111510472F9C1, 80)
    ]


class DelayReq(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x1, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # DelayReq
        BitField("originTimestamp", 100, 80)
    ]


class PdelayReq(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol PdelayReq"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x2, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 54),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # PdelayReq
        BitField("originTimestamp", 0, 80),
        BitField("reserved3", 10000, 80)

    ]


class PdelayResp(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol PdelayResp"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x3, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 54),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # PdelayResp
        BitField("requestReceiptTimestamp", 10000000, 80),
        BitField("requestingPortIdentity", 10000000, 80),

    ]


class FollowUp(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol FollowUp"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x8, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # FollowUp
        BitField('preciseOriginTimestamp', 0x888, 80),

    ]


class DelayResp(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol DelayResp"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0x9, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 54),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # DelayResp
        BitField("receiveTimestamp", 10000000, 80),
        BitField("requestingPortIdentity", 100, 80)

    ]


class PdelayRespFollowUp(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol PdelayRespFollowUp"

    MSG_TYPES = {
        0x0: "Sync",
        0x1: "DelayReq",
        0x2: "PdelayReq",
        0x3: "PdelayResp",
        0x8: "FollowUp",
        0x9: "DelayResp",
        0xA: "PdelayRespFollowUp"
    }

    FLAGS = [
        "SECURITY", "profileSpecific2", "profileSpecific1", "?",
        "?", "UNICAST", "TWO_STEP", "ALTERNATE_MASTER",
        "?", "?","FREQUENCY_TRACEABLE","TIME_TRACEABLE",
        "TIMESCALE", "UTC_REASONABLE", "LI59", "LI61"
    ]

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitEnumField("messageType", 0xA, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 54),
        ByteField("domainNumber", 0),
        XByteField("reserved1", 0),
        FlagsField("flags", 0x0200, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("reserved2", 0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        #BitField('clockIdentity', 0x888, 64),
        #BitField('sourcePortIdentity', 10000, 16),
        ShortField("sequenceId", 0),
        XByteField("control", 0),
        SignedByteField("logMessageInterval", 0),

        # PdelayRespFollowUp
        BitField("responseOriginTimestamp", 10000000, 80),
        BitField("requestingPortIdentity", 10000000, 80),
    ]


class PTP(Packet):
    """Precision Time Protocol"""
    name = "PTP protocol"
    fields_desc = [
        XBitField('transportSpecific', 0x1, 4),
        XBitField('messageType', 0x0, 4),
        XBitField('reserved0', 0x2, 4),
        XBitField('versionPTP', 0x2, 4),
        ShortField('messageLength', 0x2C),
        XBitField('domainNumber', 0x0, 8),
        XBitField('reserved1', 0x1, 8),
        ShortField('flags', 0x0),
        XBitField('correction', 0x0, 64),
        IntField('reserved2', 0x0),
        XBitField('sourcePortIdentity', 0x008063FFFF0009BA, 80),
        ShortField('sequenceId', 0x9E48),
        XBitField('PTPcontrol', 0x05, 8),
        XBitField('logMessagePeriod', 0x0F, 8),
        XBitField('originTimestamp', 0x000045B111510472F9C1, 80)
    ]

