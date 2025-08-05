-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- Copyright 2021 Michael Davidsaver, 2025 George McIntyre
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
io.stderr:write("Loading PVA...\n")

local BEACON_MESSAGE = 0
local CONNECTION_VALIDATION_MESSAGE = 1
local ECHO_MESSAGE = 2
local SEARCH_MESSAGE = 3
local SEARCH_RESPONSE_MESSAGE = 4
local AUTHNZ_MESSAGE = 5
local ACL_CHANGE_MESSAGE = 6
local CREATE_CHANNEL_MESSAGE = 7
local DESTROY_CHANNEL_MESSAGE = 8
local CONNECTION_VALIDATED_MESSAGE = 9
local GET_MESSAGE = 10
local PUT_MESSAGE = 11
local PUT_GET_MESSAGE = 12
local MONITOR_MESSAGE = 13
local ARRAY_MESSAGE = 14
local DESTROY_REQUEST_MESSAGE = 15
local PROCESS_MESSAGE = 16
local GET_FIELD_MESSAGE = 17
local MESSAGE_MESSAGE = 18
local MULTIPLE_DATA_MESSAGE = 19
local RPC_MESSAGE = 20
local CANCEL_REQUEST_MESSAGE = 21
local ORIGIN_TAG_MESSAGE = 22

-- application messages
local application_messages = {
    [BEACON_MESSAGE]  = "BEACON",
    [CONNECTION_VALIDATION_MESSAGE]  = "CONNECTION_VALIDATION",
    [ECHO_MESSAGE]  = "ECHO",
    [SEARCH_MESSAGE]  = "SEARCH",
    [SEARCH_RESPONSE_MESSAGE]  = "SEARCH_RESPONSE",
    [AUTHNZ_MESSAGE]  = "AUTHNZ",
    [ACL_CHANGE_MESSAGE]  = "ACL_CHANGE",
    [CREATE_CHANNEL_MESSAGE]  = "CREATE_CHANNEL",
    [DESTROY_CHANNEL_MESSAGE]  = "DESTROY_CHANNEL",
    [CONNECTION_VALIDATED_MESSAGE]  = "CONNECTION_VALIDATED",
    [GET_MESSAGE] = "GET",
    [PUT_MESSAGE] = "PUT",
    [PUT_GET_MESSAGE] = "PUT_GET",
    [MONITOR_MESSAGE] = "MONITOR",
    [ARRAY_MESSAGE] = "ARRAY",
    [DESTROY_REQUEST_MESSAGE] = "DESTROY_REQUEST",
    [PROCESS_MESSAGE] = "PROCESS",
    [GET_FIELD_MESSAGE] = "GET_FIELD",
    [MESSAGE_MESSAGE] = "MESSAGE",
    [MULTIPLE_DATA_MESSAGE] = "MULTIPLE_DATA",
    [RPC_MESSAGE] = "RPC",
    [CANCEL_REQUEST_MESSAGE] = "CANCEL_REQUEST",
    [ORIGIN_TAG_MESSAGE] = "ORIGIN_TAG",
}

local PVA_MAGIC = 0xCA;
local PVA_HEADER_LEN = 8;

-- control messages
local control_messages = {
    [0] = "MARK_TOTAL_BYTES_SENT",
    [1] = "ACK_TOTAL_BYTES_RECEIVED",
    [2] = "SET_BYTE_ORDER",
}

-- status codes
local status_codes = {
    [0xff] = "OK",
    [0]    = "OK",
    [1]    = "Warning",
    [2]    = "Error",
    [3]    = "Fatal Error",
}

----------------------------------------------
-- ProtoFields
----------------------------------------------

local pva = Proto("pva", "Process Variable Access")

----------------------------------------------
-- Magic, Version, Flags, Command, Control Command, Control Data, Size, Body, PVData, GUID
----------------------------------------------

local fmagic            = ProtoField.uint8(     "pva.magic",                "Magic",            base.HEX)
local fver              = ProtoField.uint8(     "pva.version",              "Version",          base.DEC)
local fflags            = ProtoField.uint8(     "pva.flags",                "Flags",            base.HEX)
local fflag_dir         = ProtoField.uint8(     "pva.direction",            "Direction",        base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end         = ProtoField.uint8(     "pva.endian",               "Byte order",       base.HEX, {[0]="LSB",[1]="MSB"}, 0x80)
local fflag_msgtype     = ProtoField.uint8(     "pva.msg_type",             "Message type",     base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented   = ProtoField.uint8(     "pva.segmented",            "Segmented",        base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd              = ProtoField.uint8(     "pva.command",              "Command",          base.HEX, application_messages)
local fctrlcmd          = ProtoField.uint8(     "pva.ctrlcommand",          "Control Command",  base.HEX, control_messages)
local fctrldata         = ProtoField.uint32(    "pva.ctrldata",             "Control Data",     base.HEX)
local fsize             = ProtoField.uint32(    "pva.size",                 "Size",             base.DEC)
local fbody             = ProtoField.bytes(     "pva.body",                 "Body")
local fpvd              = ProtoField.bytes(     "pva.pvd",                  "PVData")
local fpvdi             = ProtoField.bytes(     "pva.pvd",                  "PVData Introspection")
local fguid             = ProtoField.bytes(     "pva.guid",                 "GUID")

----------------------------------------------
-- PVData Fields
----------------------------------------------

local fpvd_field_name    = ProtoField.string(   "pva.pvd_field_name",       "Field Name")
local fpvd_type          = ProtoField.uint8(    "pva.pvd_type",             "Type Code",        base.HEX)
local fpvd_type_id       = ProtoField.uint16(   "pva.pvd_type_id",          "Type ID")

local fpvd_struct        = ProtoField.bytes(    "pva.pvd_struct",           "PVStructure")
local fpvd_field         = ProtoField.bytes(    "pva.pvd_field",            "Field")
local fpvd_value         = ProtoField.bytes(    "pva.pvd_value",            "Value")

local fpvd_debug         = ProtoField.bytes(    "pva.pvd_debug",            "Debug Info")

----------------------------------------------
-- Common Fields
----------------------------------------------

local fcid              = ProtoField.uint32(    "pva.cid",                  "Client Channel ID")
local fsid              = ProtoField.uint32(    "pva.sid",                  "Server Channel ID")
local frequest_id       = ProtoField.uint32(    "pva.request_id",           "Operation ID")
local fsubcmd           = ProtoField.uint8(     "pva.subcmd",               "Sub-command",      base.HEX)
local fsubcmd_proc      = ProtoField.uint8(     "pva.process",              "Process",          base.HEX, {[0]="",[1]="Yes"}, 0x04)
local fsubcmd_init      = ProtoField.uint8(     "pva.init",                 "Init   ",          base.HEX, {[0]="",[1]="Yes"}, 0x08)
local fsubcmd_dstr      = ProtoField.uint8(     "pva.destroy",              "Destroy",          base.HEX, {[0]="",[1]="Yes"}, 0x10)
local fsubcmd_get       = ProtoField.uint8(     "pva.get",                  "Get    ",          base.HEX, {[0]="",[1]="Yes"}, 0x40)
local fsubcmd_gtpt      = ProtoField.uint8(     "pva.getput",               "GetPut ",          base.HEX, {[0]="",[1]="Yes"}, 0x80)
local fstatus           = ProtoField.uint8(     "pva.status",               "Status",           base.HEX, status_codes)

----------------------------------------------
-- BEACON
----------------------------------------------

local fbeacon_seq       = ProtoField.uint8(     "pva.bseq",                 "Beacon sequence#")
local fbeacon_change    = ProtoField.uint16(    "pva.change",               "Beacon change count")

-- For CONNECTION_VALIDATION

local fvalid_bsize      = ProtoField.uint32(    "pva.qsize",                "Client Queue Size")
local fvalid_isize      = ProtoField.uint16(    "pva.isize",                "Client Introspection registery size")
local fvalid_qos        = ProtoField.uint16(    "pva.qos",                  "Client QoS",       base.HEX)
local fvalid_method     = ProtoField.string(    "pva.method",               "AuthZ method")
local fvalid_azflg      = ProtoField.uint8 (    "pva.authzflag",            "AuthZ Flags",      base.HEX)
local fvalid_azcnt      = ProtoField.uint8 (    "pva.authzcnt",             "AuthZ Elem‑cnt",   base.DEC)

-- For AUTHZ_REQUEST

local fauthz_request    = ProtoField.string(    "pva.authzrequest",         "AuthZ request")
local fvalid_host       = ProtoField.string(    "pva.host",                 "AuthZ host")
local fvalid_authority  = ProtoField.string(    "pva.authority",            "AuthZ authority")
local fvalid_user       = ProtoField.string(    "pva.user",                 "AuthZ name")
local fvalid_account    = ProtoField.string(    "pva.account",              "AuthZ account")
local fvalid_isTLS      = ProtoField.uint8(     "pva.isTLS",                "AuthZ isTLS")

-- For AUTHZ_RESPONSE

local fauthz_response   = ProtoField.string(    "pva.authzresponse",        "AuthZ response")

-- For AuthZ Entry Array (removed fauth_entry_index as no longer needed)

-- For SEARCH
local fsearch_seq       = ProtoField.uint32(    "pva.seq",                  "Search Sequence #")
local fsearch_addr      = ProtoField.bytes(     "pva.addr",                 "Address")
local fsearch_port      = ProtoField.uint16(    "pva.port",                 "Port")
local fsearch_mask      = ProtoField.uint8(     "pva.mask",                 "Mask",             base.HEX)
local fsearch_mask_repl = ProtoField.uint8(     "pva.reply",                "Reply",            base.HEX, {[0]="Optional",[1]="Required"}, 0x01)
local fsearch_mask_bcast= ProtoField.uint8(     "pva.ucast",                "Reply",            base.HEX, {[0]="Broadcast",[1]="Unicast"}, 0x80)
local fsearch_proto     = ProtoField.string(    "pva.proto",                "Transport Protocol")
local fsearch_count     = ProtoField.uint16(    "pva.count",                "PV Count")
local fsearch_cid       = ProtoField.uint32(    "pva.cid",                  "CID")
local fsearch_name      = ProtoField.string(    "pva.pv",                   "Name")

-- For SEARCH_RESPONSE
local fsearch_found     = ProtoField.bool(      "pva.found",                "Found")

-----------------------------------------------
--- ProtoFields variables
-----------------------------------------------

pva.fields = {
    fmagic, fver, fflags, fflag_dir, fflag_end, fflag_msgtype, fflag_segmented, fcmd, fctrlcmd, fctrldata, fsize, fbody, fpvd, fpvdi, fguid,
    fcid, fsid, frequest_id, fsubcmd, fsubcmd_proc, fsubcmd_init, fsubcmd_dstr, fsubcmd_get, fsubcmd_gtpt, fstatus,
    fbeacon_seq, fbeacon_change,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_host, fvalid_method, fvalid_authority, fvalid_account, fvalid_user, fvalid_isTLS,
    fvalid_azflg, fvalid_azcnt, fauthz_request, fauthz_response,
    fpvd_struct, fpvd_field, fpvd_field_name, fpvd_type, fpvd_value, fpvd_type_id, fpvd_debug,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_mask_repl, fsearch_mask_bcast,
    fsearch_proto, fsearch_count, fsearch_cid, fsearch_name,
    fsearch_found,
}

-----------------------------------------------
--- Normative Type Names
-----------------------------------------------

local nt_types = {
    ["epics:nt/NTScalar:1.0"] = "NTScalar",
    ["epics:nt/NTScalarArray:1.0"] = "NTScalarArray",
    ["epics:nt/NTEnum:1.0"] = "NTEnum",
    ["epics:nt/NTMatrix:1.0"] = "NTMatrix",
    ["epics:nt/NTURI:1.0"] = "NTURI",
    ["epics:nt/NameValue:1.0"] = "NameValue",
    ["epics:nt/NTTable:1.0"] = "NTTable",
    ["epics:nt/NTAttribute:1.0"] = "NTAttribute",
    ["epics:nt/NTMultiChannel:1.0"] = "NTMultiChannel",
    ["epics:nt/NTNDArray:1.0"] = "NTNDArray",
    ["epics:nt/NTHistogram:1.0"] = "NTHistogram",
    ["epics:nt/NTAggregate:1.0"] = "NTAggregate",
}

-----------------------------------------------
--- Introspection (PVData) encoding types
--- Used to determine the type before reading data
-----------------------------------------------

local TYPE_CODE_NULL = 0xFF;           -- NULL_TYPE: null field
local TYPE_CODE_ONLY_ID = 0xFE;        -- TYPE_CODE_ONLY_ID: 0xFE + ID (2 bytes)
local TYPE_CODE_FULL_WITH_ID = 0xFD;   -- TYPE_CODE_FULL_WITH_ID: 0xFD + ID (2 bytes) + FieldDesc
local TYPE_CODE_TAGGED_ID = 0xFC;      -- FULL_TAGGED_ID: 0xFC + ID (2 bytes) + tag [ Undecoded in this lua ]
local TYPE_CODE_RAW = 0xDF;            -- FieldDesc

-----------------------------------------------
--- Utility functions
-----------------------------------------------

-----------------------------------------------
--- Type Code Functions
-----------------------------------------------
--- This is the `fieldDesc` that is used to determine the type of the field
--- The following functions can be used to decode the type of the field
--- If the code is above `TYPE_CODE_RAW` then the field is a complex type
--- otherwise it is a simple type that is determined by the following functions
---

-----------------------------------------------
--- A field can be null
--- `TYPE_CODE_NULL`
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a null
----------------------------------------------
function isNull(type_code)
    return type_code == TYPE_CODE_NULL
end

-----------------------------------------------
--- A field may be determined by providing the ID of the field that is looked up in the Field Registry
--- `TYPE_CODE_ONLY_ID` <id: uint32>
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is determined by only an id
----------------------------------------------
function isOnlyId(type_code)
    return type_code == TYPE_CODE_ONLY_ID
end

-----------------------------------------------
--- A may be declared with an ID and have that declaration stored in the Field Registry for later lookup
--- `TYPE_CODE_FULL_WITH_ID` <id: uint32> <fieldDesc: uint8> ...
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is determined by providing a declaration and id to store it against
----------------------------------------------
function isFullWithId(type_code)
    return type_code == TYPE_CODE_FULL_WITH_ID
end

-----------------------------------------------
--- A field may be declared with and ID and a tag and then stored in the Field Registry for later lookup
--- `TYPE_CODE_FULL_AND_TAGGED_WITH_ID` <id: uint32> <tag: uint16> <fieldDesc: uint8> ...
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is determined by providing a declaration, and and id, and tag to store it against
----------------------------------------------
function isFullTaggedWithId(type_code)
    return type_code == TYPE_CODE_FULL_AND_TAGGED_WITH_ID
end


-----------------------------------------------
--- Alternatively the field can simply be declared directly and not stored in the Field Registry
--- This includes simple types and complex types
--- The type code is the fieldDesc!
--- <fieldDesc: uint8> ...
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a full field
----------------------------------------------
function isFull(type_code)
    return type_code < TYPE_CODE_RAW
end


-----------------------------------------------
--- Kind Functions
-----------------------------------------------
--- Once we have a fieldDesc we next need to determine what it means.
--- The following functions can be used to determine the kind of the field
--- There are 5 kinds of fields:
--- 1. Boolean
--- 2. Integer
--- 3. Float
--- 4. String
--- 5. Complex

-----------------------------------------------
--- Helper function to determine if the field is a boolean type
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a boolean type
----------------------------------------------
function isBoolType(type_code)
    return bit.band(type_code, 0xE0) == 0x00
end

-----------------------------------------------
--- Helper function to determine if the field is an integer type
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is an integer type
----------------------------------------------
function isIntType(type_code)
    return bit.band(type_code, 0xE0) == 0x20
end

-----------------------------------------------
--- Helper function to determine if the field is a float type
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a float type
----------------------------------------------
function isFloatType(type_code)
    return bit.band(type_code, 0xE0) == 0x40
end

-----------------------------------------------
--- Helper function to determine if the field is a string type
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a string type
----------------------------------------------
function isStringType(type_code)
    return bit.band(type_code, 0xE0) == 0x60
end

-----------------------------------------------
--- Helper function to determine if the field is a complex type
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a complex type
----------------------------------------------
function isComplexType(type_code)
    return bit.band(type_code, 0xE0) == 0x80
end

-----------------------------------------------
--- Array Types
-----------------------------------------------
--- Any of the 5 types of fields can be an array
--- There are three kinds of arrays:
--- 1. Variable Array: The length of the array is not specified in the declaration but if provided each time the field is used with data
--- 2. Bounded Array:  The maximum extent of the array is specified in the declaration, and the actual extent is provided each time the field is used with data
--- 3. Fixed Array:    The length of the array is specified in the declaration and the extent is fixed

-----------------------------------------------
--- Helper function to determine if the field is an array
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is an array
----------------------------------------------
function isArrayType(type_code)
    return bit.band(type_code, 0x18) ~= 0
end

-----------------------------------------------
--- Helper function to determine if the field is a variable array
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a variable array
----------------------------------------------
function isVariableArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x08
end

-----------------------------------------------
--- Helper function to determine if the field is a bounded array
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a bounded array
----------------------------------------------
function isBoundedArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x10
end

-----------------------------------------------
--- Helper function to determine if the field is a fixed array
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the field is a fixed array
----------------------------------------------
function isFixedArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x18
end

-----------------------------------------------
--- Kind Details
-----------------------------------------------
--- Depending on the kind of field we need to determine
--- the exact variant of the field it is.
--- These functions are called in the context of each of the 5
--- kinds of fields determined by the kind functions

--- Integer Types
---
--- There are 8 variants of integer types:
--- 1. 8-bit unsigned and signed   : <1 byte>
--- 2. 16-bit unsigned and signed  : <2 bytes>
--- 3. 32-bit unsigned and signed  : <4 bytes>
--- 4. 64-bit unsigned and signed  : <8 bytes>
---
--- The following functions can be used to determine the kind of the integer

-----------------------------------------------
--- getIntLen: get the length of the integer type
-----------------------------------------------
--- @param type_code number the field type code
--- @return number the length of the integer type
----------------------------------------------
function getIntLen(type_code)
    local b = bit.band(type_code, 0x03)  -- Extract bits 1-0 (not 2-1!)
    return b == 0x00 and 8 or b == 0x01 and 16 or b == 0x02 and 32 or 64
end


-----------------------------------------------
--- isIntSigned: determine if the integer type is signed
-----------------------------------------------
--- @param type_code number the field type code
--- @return boolean true if the integer type is signed
----------------------------------------------
function isIntSigned(type_code)
    return bit.band(type_code, 0x04) == 0
end


-----------------------------------------------
--- Helper function to get the name of the integer type
-----------------------------------------------
--- @param type_code number the field type code
--- @return string the name of the integer type
----------------------------------------------
function getIntName(type_code)
    local b = isIntSigned(type_code) and "int" or "uint"
    return b .. getIntLen(type_code) .. "_t"
end

-----------------------------------------------
--- Float Types
-----------------------------------------------
--- There are 2 variants of float types:
--- 1. 32-bit float             : <4 bytes>
--- 2. 64-bit double            : <8 bytes>
---
--- The following functions can be used to determine the kind of the float

-----------------------------------------------
--- Helper function to get the length of the float type
-----------------------------------------------
--- @param type_code number the field type code
--- @return number the length of the float type
----------------------------------------------
function getFloatLen(type_code)
    local b = bit.band(type_code, 0x07)
    return b == 0x02 and 32 or 64
end

-----------------------------------------------
--- Helper function to get the name of the float type
-----------------------------------------------
--- @param type_code number the field type code
--- @return string the name of the float type
----------------------------------------------
function getFloatName(type_code)
    local b = bit.band(type_code, 0x07)
    return b == 0x02 and "float" or "double"
end

-----------------------------------------------
--- Complex Types
-----------------------------------------------
--- All complex types start with a name (sometimes referred to as a type id)
--- The string is defined using the variable length pvData size encoding of either 1, 5, or 13 bytes.
--- So all complex types start with: <pvData-size: 1, 5, or 13 bytes> <pvData-string: length> ...
---
--- There are 4 variants of complex types:
--- 1. struct
--- 2. union
--- 3. any
--- 4. fixed_string
---
--- The following functions can be used to determine the kind of the complex type

-----------------------------------------------
--- Helper function to get the name of the complex type
-----------------------------------------------
--- @param type_code number the field type code
--- @return string the name of the complex type
----------------------------------------------
function getComplexName(type_code)
    local b = bit.band(type_code, 0x07)
    return b == 0x00 and "struct" or b == 0x01 and "union" or b == 0x02 and "any" or "fixed_string"
end

-----------------------------------------------
--- Putting it all together
-----------------------------------------------
--- The following functions can be used to determine the type of the field, or
--- format the fields, irrespective of the kind of field

-----------------------------------------------
--- getTypeName
-----------------------------------------------
--- @param type_code number the field type code
--- @return string the type name of the field
----------------------------------------------
function getTypeName(type_code)
    return isBoolType(type_code) and "bool" or isIntType(type_code) and getIntName(type_code) or isFloatType(type_code) and getFloatName(type_code) or isStringType(type_code) and "string" or getComplexName(type_code)
end

-----------------------------------------------
--- Format field name and type for display in protocol tree
-----------------------------------------------
--- @param type_code number the field type code
--- @param field_name string the name of the field, defaults to value if not specified
--- @param type_name string the optional "Type ID" or Normative Type string to use for complex types
--- @return string the formatted field name and type
----------------------------------------------
function formatField(type_code, field_name, type_name)
    local a = isArrayType(type_code) and "[]" or ""

    field_name = field_name or "value"
    type_name = type_name or getTypeName(type_code)
    local nt = nt_types[type_name]
    type_name = nt and nt or type_name

    return string.format("%s%s (0x%02X: %s%s)", field_name, a, type_code, type_name, a)
end

-----------------------------------------------
--- The Operation ID PVField Cache
-----------------------------------------------
--- The Field Registry is a map of request_id to a map of field_id to Field
--- The Field Registry is used to store the fields for a request
--- For each request there is at most one root field (the top level field)
--- This can be a simple field or a complex field in which case there are sub-fields, also stored against the same request_id
-----------------------------------------------
--- @field roots table this is a map of roots keyed on request_id
--- @field data table this is the map of Field-maps keyed on request_id, each sub-map is keyed on field_id
local FieldRegistry = {}

-----------------------------------------------
--- Initialize the Field Registry
-----------------------------------------------
FieldRegistry.data = {}
FieldRegistry.roots = {}

-----------------------------------------------
--- Get the root field for a request
-----------------------------------------------
--- @param request_id number the request_id to get the root field for
--- @return table the root field for the request_id
----------------------------------------------
function FieldRegistry:getRootField(request_id)
    return self.roots[request_id]
end

-----------------------------------------------
--- Create a new `Field`
-----------------------------------------------
--- - If the `type` name is specified then it is used as the type name of this `Field`.
--- - If `parent_field` is specified then the newly created `Field` is added as a child of the parent `Field`.
---   It is up to the caller to assure that the parent is of the appropriate type to accept children.
-----------------------------------------------
--- @param name string the field name
--- @param type_code number the type code
--- @param type string the string name to use as the type
--- @param len number optional number of elements in a fixed or bounded array
--- @param parent_field table the optional parent of this field
--- @return table the new `Field`
----------------------------------------------
function FieldRegistry:createField(name, type_code, type, len, parent_field)
    -- Determine the type string
    local type_string = type or getTypeName(type_code)

    -- Create Field
    local field = {
        name = name,
        type_code = type_code,
        type = type_string,
        len = len,
        sub_fields = {},
        request_id = nil,
        field_id = nil
    }

    -- If parent_field is provided, add this field as a sub-field of the parent
    if parent_field then
        table.insert(parent_field.sub_fields, field)
    end

    -- Return new Field
    return field
end

-----------------------------------------------
--- Create a new `Field` and add it to the `FieldRegistry` if `request_id` and `field_id` are specified
-----------------------------------------------
--- - If `request_id` and  `field_id` are provided then new `Field` is added to the `FieldRegistry` .
-----------------------------------------------
--- @param name string the field name
--- @param type_code number the type code
--- @param type string the string name to use as the type
--- @param len number optional number of elements in a fixed or bounded array
--- @param parent_field table the optional parent of this field, nil to specify a root Field
--- @param request_id number the storage of fields in the `FieldRegistry` is partitioned by `request_id`
--- @param field_id number the identifier of a `Field` specified in the PVAccess protocol
--- @return table the new `Field` or nil if `request_id` and `field_id` are not provided
----------------------------------------------
function FieldRegistry:addField(name, type_code, type, len, parent_field, request_id, field_id)
    local field = self:createField(name, type_code, type, len, parent_field)

    if request_id then
        -- Ensure request_id partition of Fields exists in the registry
        if not self.data[request_id] then
            self.data[request_id] = {}
        end

        -- If this field has no parent_field then set it as the root Field in this request_id
        if not parent_field then
            self.roots[request_id] = field
        end

        -- Store the field only if it has a field_id
        if field_id then
            self.data[request_id][field_id] = field
        end
    end

    return field
end

----------------------------------------------
--- Get a Field from the Field Registry
----------------------------------------------
--- Retrieves a Field identified by the given field_id from the given request_id partition of the Field Registry
----------------------------------------------
--- @param request_id number the request_id to get the field for
--- @param field_id number the field_id to get the field for
--- @return table the field for the request_id and field_id
----------------------------------------------
function FieldRegistry:getField(request_id, field_id)
    return request_id and field_id and self.data and self.data[request_id] and self.data[request_id][field_id]
end

----------------------------------------------
--- Get sub-fields of the given Field
----------------------------------------------
--- @param field table the parent Field to get the sub-Fields of
--- @return table the sub-fields of the given Field
----------------------------------------------
function FieldRegistry:getSubFields(field)
    return field.sub_fields
end

----------------------------------------------
--- Get all fields for a request_id
----------------------------------------------
--- @param request_id number the request_id to get the fields for
--- @return table the fields of the given request_id
----------------------------------------------
function FieldRegistry:getFields(request_id)
    return self.data[request_id] or {}
end

----------------------------------------------------------------
--- Expand a bitset_str:
----------------------------------------------------------------
---  * If a bit is 1 **and** none of its direct children bits are 1, we mark every descendant 1.
---  * Unions/variant‑unions do NOT cascade.
--- Returns a *new* bit‑string with the cascade applied.
--- @param request_id number the request id to reference for introspection data
--- @param bitset_str string the bitset string to fill out
--- @return string a filled out bitset string
----------------------------------------------------------------
function FieldRegistry:fillOutIndexes(request_id, bitset_str)
    local bits = {}
    for i = 1, #bitset_str do      -- copy to mutable table
        bits[i] = bitset_str:sub(i, i) == "1"
    end

    local root = self.roots[request_id]
    if not root then return bitset_str end

    -- Recursively walk the FieldDesc tree depth‑first
    local function walk(field, index)
        local start = index      -- bit index of *field* itself
        local child_idx = start + 1

        -- Determine if any direct child bits are set
        local any_child_set = false
        for _, child in ipairs(field.sub_fields or {}) do
            if bits[child_idx + 1] then any_child_set = true end
            child_idx = walk(child, child_idx)   -- recurse
        end

        -- Cascade: parent is set and no child set  ->  mark all children
        if bits[start + 1] and not any_child_set
                and isComplexType(field.type_code)
                and getComplexName(field.type_code) ~= "union"
                and getComplexName(field.type_code) ~= "any"
        then
            local mark_idx = start + 1
            for _, child in ipairs(field.sub_fields or {}) do
                bits[mark_idx + 1] = true
                mark_idx = FieldRegistry:sizeOf(child) + mark_idx
            end
        end
        return child_idx          -- how far walker advanced
    end

    walk(root, 0)

    local out = {}
    for i = 1, #bits do out[i] = bits[i] and "1" or "0" end
    return table.concat(out)
end

----------------------------------------------
-- sizeOf: count all fields and subfields
----------------------------------------------
-- @param field table the field to count the subfields for
-- @return number the total number of fields and subfields
----------------------------------------------
function FieldRegistry:sizeOf(field)
    if not field or not field.sub_fields or #field.sub_fields == 0 then
        return 1
    end

    local total = 1  -- Count the field itself
    for _, sub_field in ipairs(field.sub_fields) do
        total = total + self.sizeOf(sub_field)
    end
    return total
end
----------------------------------------------
--- Get a field by depth-first index within an request_id
----------------------------------------------
--- @param request_id number the request_id to search in
--- @param index number the zero-based index of the field to retrieve
--- @return table field the found Field
----------------------------------------------
function FieldRegistry:getIndexed(request_id, index)
    local root_field = self.roots[request_id]

    if not root_field then return nil end

    --- search from the given field down depth first, recursing when necessary
    --- @return table a List of Fields from the root to the found field
    --- @return number remaining indices space to search
    local function depthFirstTraverse(field, target_index)
        if target_index == 0 then return field, target_index end

        -- otherwise traverse the next field if there are any
        target_index = target_index - 1

        -- If we have any sub fields then check them
        for _, sub_field in ipairs(field.sub_fields) do
            local found_sub_field
            found_sub_field, target_index = depthFirstTraverse(sub_field, target_index)
            if target_index == 0 and found_sub_field then
                return found_sub_field, target_index
            end
        end

        return nil, target_index
    end

    local found_field, final_index = depthFirstTraverse(root_field, index)
    if final_index == 0 then
        return found_field
    else
        return nil
    end
end

----------------------------------------------
--- Get the full bit set for a request_id
----------------------------------------------
--- @param request_id number the request_id to get the full bit set for
--- @return string the full bit set for the request_id
----------------------------------------------
function FieldRegistry:getFullBitSet(request_id)
    local root_field = self.roots[request_id]
    if not root_field then return nil end

    local function depthFirstTraverse(field)
        local bitset_str = "1"

        -- traverse the next field if there are any
        for _, sub_field in ipairs(field.sub_fields) do
            bitset_str = bitset_str .. depthFirstTraverse(sub_field)
        end

        return bitset_str
    end

    return depthFirstTraverse(root_field)
end

----------------------------------------------
--- Get a field by depth-first index within an request_id
----------------------------------------------
--- - Starts at the root of a request_id and traverses the field graph depth first.
--- - It indexes fields it finds from 0 (root)
--- List of Fields, ... can be used to reconstruct tree for display
----------------------------------------------
--- @param request_id number the request_id to search in
--- @param index number the zero-based index of the field to retrieve
--- @return table a List of Fields from the root to the found field
----------------------------------------------
function FieldRegistry:getIndexedField(request_id, index)
    local root_field = self.roots[request_id]
    if not root_field then return nil end

    --- search from the given field down depth first, recursing when necessary
    --- @return table a List of Fields from the root to the found field
    --- @return number remaining indices space to search
    local function depthFirstTraverse(field, target_index)
        local field_info = {
            name = field.name,
            type_code = field.type_code,
            type = field.type,
            len = field.len,
        }

        -- is this field the target field
        if target_index == 0 then
            return { field_info }, target_index
        end

        -- otherwise traverse the next field if there are any
        target_index = target_index - 1

        -- If we have any sub fields then check them
        for _, sub_field in ipairs(field.sub_fields) do
            local sub_field_path
            sub_field_path, target_index = depthFirstTraverse(sub_field, target_index)
            if target_index == 0 and sub_field_path then
                table.insert(sub_field_path, 1, field_info)
                return sub_field_path, target_index
            end
        end

        -- if there are no other fields then keep the same target_index and indicate not found
        return nil, target_index
    end

    local field_path, final_index = depthFirstTraverse(root_field, index)
    return final_index == 0 and field_path or nil
end

----------------------------------------------
--- bufToBinary: get an binary string of digits from buffer.
----------------------------------------------
--- Convert a TvbRange containing N bytes of bit‑mask into a Lua string
--- where char(1) == bit 0 (top‑level field), char(2) == bit 1, …
----------------------------------------------
--- @param buf tvb to read the bytes from
--- @return string the sequence of 0's and 1's that make up the full and ordered bit string
----------------------------------------------
function bufToBinary(tvb)
    if not tvb or tvb:len() == 0 then return "" end

    local out = {}
    local idx = 1
    -- traverse bytes in natural wire order (byte0, byte1 …)
    for byte_i = 0, tvb:len() - 1 do
        local b = tvb(byte_i, 1):uint()
        -- LSB‑first
        for bit = 0, 7 do
            out[idx] = ((b >> bit) & 0x01) == 1 and "1" or "0"
            idx = idx + 1
        end
    end
    return table.concat(out)
end



----------------------------------------------
--- getUint: get an unsigned integer with the correct byte order
----------------------------------------------
--- @param buf table to read the uint from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return number the unsigned integer
----------------------------------------------
local function getUint(buf, is_big_endian)
    return buf:len() == 1 and buf:uint() or (is_big_endian == nil or is_big_endian) and (buf:len() == 2 and buf:uint() or buf:uint64():tonumber()) or (buf:len() == 2 and buf:le_uint() or buf:le_uint64():tonumber())
end

----------------------------------------------
--- getUint32: get an unsigned 32-bit integer with the correct byte order
----------------------------------------------
--- @param buf table to read the int64 from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return number the unsigned 32-bit integer
----------------------------------------------
local function getUint32(buf, is_big_endian)
    return getUint(buf(0,2), is_big_endian)
end

----------------------------------------------
--- getUint64: get an unsigned 64-bit integer with the correct byte order
----------------------------------------------
--- @param buf table to read the int64 from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return number the unsigned 64-bit integer
----------------------------------------------
local function getUint64(buf, is_big_endian)
    return getUint(buf(0,4), is_big_endian)
end


-----------------------------------------------
--- decodeSize: decode a size from a TvbRange buffer using 3-tier encoding
--- Tier 1: 1 byte (0x00-0xFD) → value 0-253
--- Tier 2: 5 bytes (0xFF + 4-byte signed int32) → value 255-2^31-2
--- Tier 3: 13 bytes (0xFF + 0x7FFFFFFF + 8-byte signed int64) → value 2^31-1 to 2^63-1
----------------------------------------------
--- @param buf table whose first byte is the Size
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return number size
--- @return table remaining buffer
-----------------------------------------------------------------
local function decodeSize(buf, is_big_endian, is_nullable)
    if not buf or buf:len() < 1 then return 0, buf end

    local first_limit = not is_nullable and 0xFF or is_nullable == true and 0xFE or 0xFF

    if first_limit == 0xFE and buf:range(0,1):uint() == 0xFF then return 0, buf:len() > 1 and buf:range(1) or nil end

    -- 1. fast path: single‑byte size 0‑253 or 254 depending on whether nullable
    local first = buf:range(0,1):uint()
    if first < first_limit then
        return first, buf:len() > 1 and buf:range(1) or nil
    end

    -- 2. extended 32‑bit form (5 bytes total)
    local v32 = (is_big_endian and
            buf:range(1,4):int()  or    -- signed BE int32
            buf:range(1,4):le_int())    -- signed LE int32

    if v32 ~= 0x7FFFFFFF then           -- ordinary 32‑bit size
        assert(v32 >= 0, "negative size")
        return v32,  buf:len() > 5 and buf:range(5) or nil              -- drop 5 bytes
    end

    -- 3. extended 64‑bit form (13 bytes total)
    local v64 = (is_big_endian and
            buf:range(5,8):int64()  or  -- signed BE int64 (Int64 obj)
            buf:range(5,8):le_int64())  -- signed LE int64
    assert(v64:tonumber() >= 0, "negative size")

    return v64,  buf:len() > 13 and buf:range(13) or nil                 -- drop 13 bytes
end

----------------------------------------------
--- getBitSet: take the next byte as a count, followed by that many bytes of the bitset
----------------------------------------------
--- @param buf table to read the bitset from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return table the remaining buffer
--- @return table the bitset
----------------------------------------------
local function getBitSet(buf, is_big_endian)
    local bitset_count
    bitset_count, buf = decodeSize(buf, is_big_endian)
    if buf:len() < bitset_count then
        return nil, buf
    else
        return buf:len() == bitset_count and buf or buf:range(0, bitset_count), buf:range(bitset_count)
    end
end

----------------------------------------------
--- pvaDecodeTypeCode: decode the type code from the buffer
----------------------------------------------
--- @param buf table to read the type code from
--- @param tree table to add the type code to
--- @return table the remaining buffer
--- @return number the type code
----------------------------------------------
local function pvaDecodeTypeCode(buf, tree)
    if buf:len() < 1 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "PVData Type Code: Truncated")
        return nil, nil
    end

    local type_code = buf:range(0, 1):uint()
    if type_code > TYPE_CODE_RAW and type_code < TYPE_CODE_TAGGED_ID then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, string.format("PVData: Invalid Type Code: %02x", type_code))
        return nil, nil
    end

    return type_code, buf:len() > 1 and buf:range(1) or nil
end


----------------------------------------------
--- decodeString: extract a string and return that string, and the remaining buffer
--- string is encoded as a size followed by the actual string
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param is_big_endian: true if the buffer is big endian
--- @return string the string
--- @return table the remaining buffer
----------------------------------------------
local function decodeString(buf, is_big_endian)
    if not buf or buf:len() == 0 then
        return nil, buf
    end

    local len, remaining_buf = decodeSize(buf, is_big_endian, true)
    if len == 0 then return nil, remaining_buf end

    -- Check if we have enough bytes for the string
    if remaining_buf == nil or remaining_buf:len() < len then
        -- Not enough data, return what we have as string
        local partial_range = buf(0, math.min(len, buf:len()))
        return partial_range:string(), nil
    end

    local string_range = remaining_buf(0, len)
    local string_value = string_range:string()

    if len == remaining_buf:len() then
        return string_value, nil
    else
        return string_value, remaining_buf:range(len)
    end
end

----------------------------------------------
--- getDataForType: get the string representation of the data pointed to by buf
----------------------------------------------
--- @param buf table the buffer to read from
--- @param is_big_endian boolean endianness
--- @param type_code number the type code
--- @return string the string representation of the data
--- @return number the number of bytes the data took on the wire
----------------------------------------------
function getDataForType(buf, is_big_endian, type_code)
    -- only for bool, int, float, and string scalars
    local value = ""
    local size = 1
    if not buf or buf:len() == 0 then return end

    if isStringType(type_code) then
        local remaining_buf
        value, remaining_buf = decodeString(buf, is_big_endian)
        if not remaining_buf then return value, 0 end
        size = buf:len() - remaining_buf:len()
    else
        if isBoolType(type_code) then
            value = tostring(buf(0,1):uint() ~= 0)

        elseif isIntType(type_code) then
            local the_int
            local signed = isIntSigned(type_code)
            size = getIntLen(type_code) / 8
            if is_big_endian then
                the_int = size == 8 and (signed and buf(0,size):int64() or buf(0,size):uint64()) or (signed and buf(0,size):int() or buf(0,size):uint())
            else
                the_int = size == 8 and (signed and buf(0,size):le_int64() or buf(0,size):le_uint64()) or (signed and buf(0,size):le_int() or buf(0,size):le_uint())
            end
            value = tostring(the_int)

        elseif isFloatType(type_code) then
            local the_float
            size = getFloatLen(type_code) / 8
            the_float = is_big_endian and buf(0,size):float() or buf(0,size):le_float()
            value = tostring(the_float)
        end
    end

    return value, size
end

----------------------------------------------
--- displayDataForType: display the data for a type
----------------------------------------------
--- @param buf table the buffer to read from
--- @param is_big_endian boolean endianness
--- @param type_code number the type code that determines what we'll find in buf
--- @param tree any the Protocol tree to add the decoded data information to
--- @param label string the label to use for the data any label for the data that has been determined before (defaults to "value")
--- @param len number the length of the data to read from the buffer
--- @return table the remaining buffer
----------------------------------------------
function displayDataForType(buf, is_big_endian, type_code, tree, label, len)
    -- only for non complex types
    local value
    local size = 0
    if not isArrayType(type_code) then
        -- scalar
        value, size = getDataForType(buf, is_big_endian, type_code)
        if not buf then
            tree:add(string.format(label .. ": %s", value))
        else
            tree:add(buf(0, size), string.format(label .. ": %s", value))
        end
    else
        -- get count
        local ar_buf
        if isVariableArrayType(type_code) or isBoundedArrayType(type_code) then
            -- read len
            len, ar_buf = decodeSize(buf, is_big_endian)
        end
        if not len then
            return buf
        end

        local ar_tree = tree:add(buf(0, 1), label)
        if len == 0 then
            return ar_buf
        end

        -- Add the len encoding to the size
        size = size + buf:len() - ar_buf:len()

        -- loop over data
        for i = 0, len - 1 do
            -- display
            local el_size
            local el_label = "[" .. i .. "]"
            value, el_size = getDataForType(ar_buf, is_big_endian, type_code)
            if el_size == 0 or not value then return nil end
            ar_tree:add(ar_buf(0, el_size), string.format(el_label .. ": %s", value))
            ar_buf = ar_buf:range(el_size)
            size = size + el_size
        end
    end

    return buf and buf:len() > size and buf:range(size) or nil
end

----------------------------------------------
--- pvaDecodeIntrospectionData: decode the introspection data into a Protocol tree representing the data structure
----------------------------------------------
--- @param buf table the buffer to read from
--- @param tree any the Protocol tree to add the decoded data information to
--- @param is_big_endian boolean is the data to be decoded big-endian
--- @param request_id number this is the request id to be used to store the full introspection data against
--- @param name string the name of the field in the parent field
--- @param parent_field table the parent field
--- @param sub_type_id_buf table this is the pointer into the buffer to where the type_id was found so we can reference it when we add it to the tree
--- @param extras string the extras to add to the field name e.g. where to store the field (→2) or where to retrieve the field (←2)
--- @return table the field
--- @return table the remaining buffer
----------------------------------------------
local function pvaDecodeIntrospectionData(buf, tree, is_big_endian, request_id, name, parent_field, sub_type_id_buf, extras)
    display = display or true
    extras = extras or ""
    local type_code_buf = sub_type_id_buf or buf
    local is_sub_field = sub_type_id_buf ~= nil
    local sub_field_offset = 1
    if is_sub_field then sub_field_offset = type_code_buf:len() - buf:len() + 1 end

    -- decode type code (either a simple fieldDesc or an introspection type code that shows how to determine the fieldDesc)
    local type_code
    type_code, buf = pvaDecodeTypeCode(buf, tree)

    local field_id, tag, len, field_desc, field

    -- if the type code is only an id, then we need to get Field definition from the registry using the id
    local is_id = isOnlyId(type_code)
    -- if the type code is a full field with an id, then decode the full Field definition then store it in the registry with the id
    local is_f_id = isFullWithId(type_code)
    -- if the type code is a full field with an id and a tag, then decode the full Field definition and tag then store it in the registry with the id
    local is_ft_id = isFullTaggedWithId(type_code)
    -- if the type code is a full field, then use this type_code as a raw Field definition (fieldDesc) (simple type or complex type (struct, union, etc), including optional array variants)
    local is_f = isFull(type_code)

    -- if the type code has an ID, then we need to get the ID from the buffer
    if is_f_id or is_ft_id or is_id then
        -- get ID
        if not buf or buf:len() < 3 then return field, nil end
        field_id = getUint32(buf, is_big_endian)
        extras = string.format(" → %d", field_id)
        buf = buf:range(2)
    end

    -- if the type code has a tag, then we need to get the tag from the buffer
    if is_ft_id then
        -- get tag
        if not buf then return field, nil end
        tag, buf = decodeSize(buf, is_big_endian)
        extras = extras .. string.format("/%d", tag)
    end

    -- if the type code is only an id, then we need to get Field definition from the registry using the id
    if is_id then
        -- retrieve from registry
        field = FieldRegistry:getField(request_id, field_id)
        extras = string.format(" ← %d", field_id)
    end

    -- if the type code is a full field definition, then we need to decode the field definition from the buffer
    if is_f or is_f_id or is_ft_id then
        if is_f then
            -- if this is a full field definition, then use this `TypeCode` as a raw Field definition (fieldDesc)
            field_desc = type_code
        elseif is_f_id or is_ft_id then
            -- otherwise, if this is a full field definition with ID we still need to get the actual fieldDesc from the buffer
            field_desc = buf(0,1):uint()
            if not buf or buf:len() == 1 then return field, nil end
            buf = buf:range(1)
        end

        -- if the field is an fixed or bounded array, then we need to get the array length/bounds
        local is_foba_id = isFixedArrayType(field_desc) or isBoundedArrayType(field_desc)
        if is_foba_id then
            -- get array len/bounds
            len, buf = decodeSize(buf, is_big_endian)
            if not len then return field, nil end
            extras = extras .. string.format("[%d]", len)
        end

        -- if the field is a simple type
        if not isComplexType(field_desc) then
            -- We can make a Field directly from the fieldDesc and len (if it's an array) and add it to the Field Registry
            field = FieldRegistry:addField(name, field_desc, nil, len, parent_field, request_id, field_id)
            -- add the field to the tree marking the whole extent of the field
            local range = type_code_buf(0, sub_field_offset)
            local field_name = formatField(field.type_code, field.name, field.type)
            tree:add(range, field_name)
        else
            -- if the field is a complex type, then we need to get the type id (a.k.a. the app level name for the complex type.  e.g. timestamp_t, control_t, etc)
            -- read using the normal string decoding (size followed by the string)
            local type_id
            local type_id_buf = buf
            type_id, buf = decodeString(buf, is_big_endian)

            -- now we can make the Field using the fieldDesc, len (if it's an array) and type_id and add it to the Field Registry
            field = FieldRegistry:addField(name, field_desc, type_id, len, parent_field, request_id, field_id)

            -- add the field to the tree marking the whole extent of the field.  Add the extras to the field name (extras are only valid for complex types)
            -- we calculate the range by subtracting the length of the remaining buffer from the length of the buffer when we started decoding the field's initial type code
            local range = type_code_buf(0, type_code_buf:len() - buf:len() + 1)
            local field_name = formatField(field.type_code, field.name, field.type) .. extras
            local sub_tree
            sub_tree = tree:add(range, field_name)

            -- As this is a complex type it has sub-fields, so we need to get the field count
            local count
            count, buf = decodeSize(buf, is_big_endian)
            if not buf then return field, nil end

            -- loop over the sub-fields
            for _ = 1, count do
                -- decode the sub-field name, which becomes the `name` of the field in this function on recursion
                local sub_field_name
                type_id_buf = buf
                sub_field_name, buf = decodeString(buf, is_big_endian)
                if not buf then return nil, nil end
                -- decode the sub-field and display in the sub-tree storing any type define definitions with IDs in the Field Registry
                _, buf = pvaDecodeIntrospectionData(buf, sub_tree, is_big_endian, request_id, sub_field_name, field, type_id_buf, extras)
            end
        end
    end

    return field, buf
end

----------------------------------------------
--- Decode fieldDesc to determine how to decode the data that follows into the given tree
----------------------------------------------
--- Fist decode the fieldDesc to determine the Field to display
--- Then decode the data that follows into the given tree
----------------------------------------------
--- @param buf any message to decode
--- @param tree any the root tree to attach the decoded data to
--- @param is_big_endian boolean is the data to be decoded big-endian
--- @param request_id number this is the request id to be used to store pull introspection data from
--- @return table the Field
--- @return table the remaining buffer
local function pvaDecodePVDataType(buf, tree, is_big_endian, request_id)
    local field, data_buf
    field, data_buf = pvaDecodeIntrospectionData(buf, tree, is_big_endian, request_id, nil, nil, nil, nil)
    return data_buf
end

----------------------------------------------
--- pruneUncommonRoots: prune the trees that are not common to to both the
----------------------------------------------
--- current field path and the previous field path.
--- This is used when we encounter a new field with different parents and we need
--- to know where to attach the new tree.
--- We prune back all parent trees that are different, then add the new tree to the common parent.
----------------------------------------------
--- @param trees table the trees to prune
--- @param field_path table the field path
--- @param last_field_path table the last field path
--- @return table the pruned trees
--- @return number the last common position
function pruneUncommonRoots(trees, field_path, last_field_path)
    if not trees or not last_field_path then return trees, field_path end

    local  last_common_pos = 1
    -- prune back all parent trees that are different
    if #trees > 1 and  #last_field_path > 1 then
        for tree_pos = 2, #trees do
            if tree_pos > #field_path then
                -- these are bigger than the new file path so remove them
                table.remove(trees)
                last_common_pos = tree_pos -1
            else
                local last_field_info = last_field_path[tree_pos]
                local current_field_info = field_path[tree_pos]
                if last_field_info.name ~= current_field_info.name then
                    last_common_pos = tree_pos -1
                    for _ = #trees, tree_pos, -1 do
                        -- prune back old trees
                        table.remove(trees)
                        break
                    end
                end
            end
        end
    end

    return  trees, last_common_pos
end

----------------------------------------------
--- addRequiredRoot: add a new tree to the trees list
----------------------------------------------
--- Only add a new tree if the current field position (depth) is
--- not the same as the tree-depth we've already deployed.
--- This means that we won't add a new tree when its already added.
--- This is used to add new complex fields to the tree.
----------------------------------------------
--- @param buf table the buffer to decode from
--- @param trees table the trees to add the new tree to
--- @param current_field_pos number the current field position
--- @param label string the label to add to the tree
----------------------------------------------
function addRequiredRoot(buf, trees, current_field_pos, label)
    local trees_len = #trees
    if trees_len ~= current_field_pos then
        local current_tree = trees[trees_len]
        if current_tree then
            if not buf then
                table.insert(trees, current_tree:add(label)) else
                table.insert(trees, current_tree:add(buf(0,1), label))
            end
        end
    end
end

----------------------------------------------
-- decodeStatus: decode the given message body to extract and display the status
----------------------------------------------
--- @param buf: the buffer to read the status from
--- @param tree: the tree node to display the status in
--- @param is_big_endian is the byte stream big endian
--- @return table the remaining buffer after reading the status
----------------------------------------------
local function decodeStatus (buf, tree, is_big_endian)
    local status_code = buf(0,1):uint()
    local sub_tree = tree:add(fstatus, buf(0,1))
    buf = buf:len() > 1 and buf(1) or buf

    if status_code ==0xFF then
        return buf
    else
        local message, stack
        message, buf = decodeString(buf, is_big_endian)
        stack, buf = decodeString(buf, is_big_endian)
        if not message then
            sub_tree:append_text("nil")
        else
            sub_tree:append_text(message)
        end
        if (status_code ~=0 and stack and stack:len()>0) then
            sub_tree:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack)
        end
        return buf
    end
end


----------------------------------------------
--- decodePVField: decode the given message body into the given root tree node
----------------------------------------------
--- @param buf table the buffer to decode from
--- @param root_tree table the root tree to decode into
--- @param is_big_endian boolean is the byte stream big endian
--- @param request_id number the request id
--- @param bitset_str string the bitset to decode
----------------------------------------------
function decodePVField(buf, tree, is_big_endian, request_id, bitset_str, root_field)
    -- Expand the bitset once, per PVXS cascade semantics
    root_field = root_field or FieldRegistry:getRootField(request_id)
    if not root_field then
        tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Can't decode PVData without cached Introspection Data. ID: " .. math.floor(request_id))
        return
    end

    local function recurse(field, index, parent_incl, parent_tree)
        local children_check = not parent_tree and true or false
        local is_complex_field = isComplexType(field.type_code)
        local included = parent_incl or (bitset_str:sub(index+1, index+1) == "1")
        if not included and not is_complex_field then return index + 1 end

        local my_tree = parent_tree

        if not is_complex_field then
            if not children_check then
                buf = displayDataForType(buf, is_big_endian, field.type_code, my_tree, field.name, field.len)
            end
            return index + 1, true
        else
            if not children_check then
                local test_child_idx = index + 1
                local has_visible_children = false
                for _, child in ipairs(field.sub_fields or {}) do
                    test_child_idx, has_visible_children = recurse(child, test_child_idx, included) -- check if has visible children
                    if has_visible_children then
                        break
                    end
                end

                if has_visible_children then
                    local label = formatField(field.type_code, field.name, field.type)
                    if not buf then
                        my_tree = parent_tree:add(label)
                    else
                        my_tree = parent_tree:add(buf(0,0), label)   -- zero‑len TvbRange for header
                    end
                end
            end

            local child_idx = index + 1
            local has_visible_children = false
            for _, child in ipairs(field.sub_fields or {}) do
                child_idx, has_visible_children = recurse(child, child_idx, included, my_tree)
                if children_check and has_visible_children then
                    return child_idx, true
                end
            end
            return child_idx
        end
    end

    recurse(root_field, 0, false, tree)
end


----------------------------------------------
--- pvaDecodePVData: decode the given message body into the given packet and root tree node
----------------------------------------------
--- Use the given bitset to select which fields to display
--- The bitset sometimes does not contain all the field set for complex types with sub-fields
--- so we expand the bitset to include all the fields using FieldRegistry:expandBitSet
--- The bitset is then used to decode the fields using decodePVField
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param tree: the tree node to decode into
--- @param is_big_endian boolean is the byte stream big endian
--- @param request_id: the request id
--- @param bitset: the bitset to decode
----------------------------------------------
function pvaDecodePVData(buf, tree, is_big_endian, request_id, bitset, root_field)
    local bitset_str = ""
    if bitset then
        bitset_str = bufToBinary(bitset)
        tree:add(bitset, string.format("Changed BitSet (%d bytes): %s", bitset:len(), bitset_str))
        bitset_str = FieldRegistry:fillOutIndexes(request_id, bitset_str)
    end

    decodePVField(buf, tree, is_big_endian, request_id, bitset_str, root_field)
end


----------------------------------------------
--- decodeSubCommand: decode the sub command from the buffer
----------------------------------------------
--- @param buf any message to decode
--- @param pkt any the packet to decode
--- @param tree any the root tree to attach the decoded data to
--- @param is_big_endian boolean is the data to be decoded big-endian
--- @param cmd number the command to decode
--- @param for_client boolean if this is a client message
--- @return number the request id
--- @return number the sub command
--- @return table the remaining buffer
----------------------------------------------
local function decodeSubCommand(buf, pkt, tree, is_big_endian, cmd, for_client)
    local sid, request_id

    -- optionally get client sid
    if for_client ~= nil and for_client then
        if buf:len() < 9 then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Client Op Decoder: Truncated Command Header")
            return nil, nil, nil
        end
        sid = getUint64(buf(0, 4), is_big_endian)
        tree:add(fsid, buf(0, 4), sid)
        buf = buf:range(4)
    end

    -- get request_id
    if buf:len() < 5 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Server Op Decoder: Truncated Command Header")
        return nil, nil, nil
    end

    request_id = getUint64(buf(0, 4), is_big_endian)
    tree:add(frequest_id, buf(0, 4), request_id)
    buf = buf:range(4)

    -- get sub command
    local sub_command = buf(0, 1):uint()
    local sub_tree = tree:add(fsubcmd, buf(0, 1), sub_command)
    sub_tree:add(fsubcmd_proc, buf(0, 1), sub_command)
    sub_tree:add(fsubcmd_init, buf(0, 1), sub_command)
    sub_tree:add(fsubcmd_dstr, buf(0, 1), sub_command)
    sub_tree:add(fsubcmd_get,  buf(0, 1), sub_command)
    sub_tree:add(fsubcmd_gtpt, buf(0, 1), sub_command)

    -- update cols info
    local cname = application_messages[cmd]
    if for_client ~= nil and for_client then
        pkt.cols.info:append(string.format("%s(sid=%u, request_id=%u, sub=%02x), ", cname, sid, request_id, sub_command))
    else
        pkt.cols.info:append(string.format("cmd=%02x %s(request_id=%u, sub=%02x)", cmd , cname, request_id, sub_command))
    end

    if buf:len() == 1 then
        return request_id, sub_command, nil
    else
        return request_id, sub_command, buf:range(1)
    end
end

----------------------------------------------
--- skipNextElement: skip the next element and return the remaining buffer
--- read the size of the element then skip that many bytes
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param is_big_endian: true if the buffer is big endian
--- @return table the remaining buffer or nil if this is the last element
----------------------------------------------
local function skipNextElement(buf, is_big_endian)
    local len, remaining_buf = decodeSize(buf, is_big_endian)
    return len ~= remaining_buf:len() and remaining_buf(len + 1) or nil
end

----------------------------
-- PVData decoders
----------------------------

----------------------------------------------
--- isAuthMethod: Helper function to identify authentication method strings
----------------------------------------------
--- @param method_name string the method name to check
--- @param prev_was_method boolean if the previous was a valid method name
--- @return boolean true if the given method name is a valid authentication method
----------------------------------------------
local function isAuthMethod(method_name, prev_was_method)
    if not method_name then return false end

    -- Handle both TvbRange and string types
    local method_str = type(method_name) == "string" and method_name or method_name:string()

    local lower_case_method_name = method_str:lower()

    -- Strong method indicators
    local strong_methods = {"x509", "ca"}
    for _, method in ipairs(strong_methods) do
        if lower_case_method_name == method then return true end
    end

    -- "anonymous" is typically a username unless it's clearly in method position
    if lower_case_method_name == "anonymous" then return prev_was_method end

    return false
end

----------------------------
-- command decoders
----------------------------

----------------------------------------------
-- pvaClientSearchDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientSearchDecoder (buf, pkt, tree, is_big_endian)
    local SEARCH_HEADER_SIZE = 26
    local raw_sequence_number = buf(0,4)
    local sequence_number = getUint(raw_sequence_number, is_big_endian)
    local port = getUint(buf(24,2), is_big_endian)
    pkt.cols.info:append("SEARCH(".. sequence_number)

    tree:add(fsearch_seq, raw_sequence_number, sequence_number)

    local raw_mask = buf(4,1)
    local mask = tree:add(fsearch_mask, raw_mask)
    mask:add(fsearch_mask_repl, raw_mask)
    mask:add(fsearch_mask_bcast, raw_mask)
    tree:add(fsearch_addr, buf(8,16))
    tree:add(fsearch_port, buf(24,2), port)

    local n_protocols

    -- get protocols list
    n_protocols, buf = decodeSize(buf(SEARCH_HEADER_SIZE), is_big_endian)
    for _=0, n_protocols -1 do
        local name
        name, buf = decodeString(buf, is_big_endian)
        tree:add(fsearch_proto, name)
    end

    -- get pvs list
    local raw_n_pv = buf(0,2)
    local n_pvs = getUint(raw_n_pv, is_big_endian)
    tree:add(fsearch_count, raw_n_pv, n_pvs);
    if n_pvs >0 then
        buf = buf(2)

        for _=0, n_pvs -1 do
            local name
            local raw_cid = buf(0,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            name, buf = decodeString(buf(4), is_big_endian)
            tree:add(fsearch_name, name)

            pkt.cols.info:append(', '..cid..":'"..name.."'")
        end
    end
    pkt.cols.info:append("), ")
end

----------------------------------------------
--- pvaServerBeaconDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerBeaconDecoder (buf, pkt, tree, is_big_endian)
    local raw_beacon_header = buf(0,12)
    tree:add(fguid, raw_beacon_header)
    local sequence_number = getUint(buf(13,1), is_big_endian)
    local change = getUint(buf(14,2), is_big_endian)
    local port = getUint(buf(32,2), is_big_endian)
    tree:add(fbeacon_seq, buf(13,1), sequence_number)
    tree:add(fbeacon_change, buf(14,2), change)
    tree:add(fsearch_addr, buf(16,16))
    tree:add(fsearch_port, buf(32,2), port)

    pkt.cols.info:append("BEACON(0x".. raw_beacon_header ..", ".. sequence_number ..", "..change..")")

    local proto
    proto, buf = decodeString(buf(34), is_big_endian)
    tree:add(fsearch_proto, proto)
end

----------------------------------------------
--- pvaServerSearchResponseDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerSearchResponseDecoder (buf, pkt, tree, is_big_endian)
    local sequence_number = getUint(buf(12,4), is_big_endian)
    local port = getUint(buf(32,2), is_big_endian)
    pkt.cols.info:append("SEARCH_RESPONSE(".. sequence_number)

    tree:add(fguid, buf(0,12))
    tree:add(fsearch_seq, buf(12,4), sequence_number)
    tree:add(fsearch_addr, buf(16,16))
    tree:add(fsearch_port, buf(32,2), port)

    local proto
    proto, buf = decodeString(buf(34), is_big_endian)
    tree:add(fsearch_proto, proto)

    tree:add(fsearch_found, buf(0, 1))

    local n_pvs = getUint(buf(1,2), is_big_endian)
    if n_pvs >0 then
        buf = buf(3)
        for i=0, n_pvs -1 do
            local raw_cid = buf(i*4,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            pkt.cols.info:append(', '..cid)
        end
    end
    pkt.cols.info:append(")")

end

----------------------------------------------
--- pvaClientValidateDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientValidateDecoder (buf, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local bsize  = getUint(buf(0,4), is_big_endian)
    local isize = getUint(buf(4,2), is_big_endian)
    local qos = getUint(buf(6,2), is_big_endian)
    tree:add(fvalid_bsize, buf(0,4), bsize)
    tree:add(fvalid_isize, buf(4,2), isize)
    tree:add(fvalid_qos, buf(6,2), qos)

    local method_range = buf(8)
    local method
    method, buf = decodeString(method_range, is_big_endian)

    -- Declare variables for authz processing
    local n_authz = 0
    local has_authz_extensions = false

    -- extensions to the AUTHZ message
    if (buf and buf:len() > 1)
    then
        local authzmessage, authzflags
        authzmessage = buf(0,1):uint()
        if authzmessage == 0xfd
        then
            buf = buf(3)
        end
        -- Add authz flags at the main level (applies to all entries)
        tree:add(fvalid_azflg,  buf(1,1))
        authzflags = buf(1,1):uint()
        n_authz = buf(2,1):uint()
        buf = buf(3)
        has_authz_extensions = true
    end

    -- Add appropriate info message based on method
    if method then
        local method_str = type(method) == "string" and method or method:string()
        if method_str:lower() == "x509" then
            pkt.cols.info:append("X509 AUTHZ, ")
        elseif has_authz_extensions then
            if n_authz == 2 then
                pkt.cols.info:append("CA AUTHZ, ")
            elseif n_authz == 3 then
                pkt.cols.info:append("PVA AUTHZ, ")
            end
        end
    elseif has_authz_extensions then
        if n_authz == 2 then
            pkt.cols.info:append("CA AUTHZ, ")
        elseif n_authz == 3 then
            pkt.cols.info:append("PVA AUTHZ, ")
        end
    end

    -- Start with basic auth entry for the method
    local entry_tree = tree:add("AuthZ Entry 1")
    if method then
        entry_tree:add(fvalid_method, method_range, method)
    end

    -- Process authz extensions if present
    if has_authz_extensions
    then
        local peer, authority, account
        if n_authz == 2
        then
            buf = skipNextElement(buf, is_big_endian)
            buf = skipNextElement(buf, is_big_endian)

            local account_range = buf
            account, buf = decodeString(account_range, is_big_endian)
            local peer_range = buf
            peer, buf = decodeString(peer_range, is_big_endian)

            -- Add additional fields to the existing auth entry
            entry_tree:add(fvalid_user, account_range, account)
            entry_tree:add(fvalid_host, peer_range, peer)

        elseif n_authz == 3
        then
            buf = skipNextElement(buf, is_big_endian)
            buf = skipNextElement(buf, is_big_endian)
            buf = skipNextElement(buf, is_big_endian)

            local peer_range = buf
            peer, buf = decodeString(peer_range, is_big_endian)
            local authority_range = buf
            authority, buf = decodeString(authority_range, is_big_endian)
            local account_range = buf
            account, buf = decodeString(account_range, is_big_endian)

            -- Add additional fields to the existing auth entry
            entry_tree:add(fvalid_host, peer_range, peer)
            -- Only show AuthZ authority field when method is not 'ca'
            if method then
                local method_str = type(method) == "string" and method or method:string()
                if method_str:lower() ~= "ca" then
                    entry_tree:add(fvalid_authority, authority_range, authority)
                    entry_tree:add(fvalid_isTLS, 1)
                end
            end
            entry_tree:add(fvalid_user, account_range, account)
        end
    end
end

----------------------------------------------
--- pvsServerValidateDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvsServerValidateDecoder (buf, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local VALIDATION_HEADER_LEN = 7

    if buf:len() >= VALIDATION_HEADER_LEN then
        -- Parse header: 4 bytes buffer size, 2 bytes introspection size, 1 byte flags
        local bsize = getUint(buf(0,4), is_big_endian)
        local isize = getUint(buf(4,2), is_big_endian)
        local flags = buf(6,1):uint()
        tree:add(fvalid_bsize, buf(0,4), bsize)
        tree:add(fvalid_isize, buf(4,2), isize)
        tree:add(fvalid_azflg, buf(6,1), flags)

        -- Parse all strings into a table first
        if buf:len() > VALIDATION_HEADER_LEN then
            local remaining = buf(VALIDATION_HEADER_LEN)
            local strings = {}

            -- Collect all strings
            while remaining and remaining:len() > 0 do
                local str
                str, remaining = decodeString(remaining, is_big_endian)
                if str and str:len() > 0 then
                    table.insert(strings, str)
                else
                    break
                end
            end

            -- Process strings into auth entries
            if #strings > 0 then
                local auth_entries = {}
                local current_entry = {}
                local has_seen_method = false

                for _, method_name in ipairs(strings) do
                    if isAuthMethod(method_name, has_seen_method) then
                        -- This is a method string
                        if current_entry.method then
                            -- Current entry already has a method, start new entry
                            table.insert(auth_entries, current_entry)
                            current_entry = {method = method_name }
                        else
                            -- Add method to current entry
                            current_entry.method = method_name
                        end
                        has_seen_method = true
                    else
                        -- This is likely a name/user string
                        if not current_entry.name then
                            current_entry.name = method_name
                        else
                            -- Could be additional data like response
                            current_entry.response = method_name
                        end
                    end
                end

                -- Add the last entry
                if current_entry.method or current_entry.name or current_entry.response then
                    table.insert(auth_entries, current_entry)
                end

                -- Create subtrees for each auth entry
                for i, entry in ipairs(auth_entries) do
                    local entry_tree = tree:add("AuthZ Entry " .. i)

                    if entry.name then
                        entry_tree:add(fvalid_user, entry.name)
                    end
                    if entry.method then
                        entry_tree:add(fvalid_method, entry.method)
                    end
                    if entry.response then
                        entry_tree:add(fauthz_response, entry.response)
                    end
                end
            end

            -- Handle any remaining unprocessed data
            if remaining and remaining:len() > 0 then
                tree:add(fbody, remaining)
            end
        end
    else
        -- Too short, show as raw body
        tree:add(fbody, buf)
    end
end

----------------------------------------------
--- pvaClientCreateChannelDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientCreateChannelDecoder (buf, pkt, tree, is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local n_pvs = getUint32(buf, is_big_endian)
    buf = buf(2)

    for i=0, n_pvs -1 do
        local cid = getUint64(buf, is_big_endian)
        tree:add(fsearch_cid, buf(0,4), cid)
        local name
        name, buf = decodeString(buf(4), is_big_endian)
        if name then
            tree:add(fsearch_name, name)
            if i< n_pvs -1 then pkt.cols.info:append("', '") end
            local name_str = type(name) == "string" and name or name:string()
            pkt.cols.info:append("'"..name_str)
        end
    end
    pkt.cols.info:append("'), ")
end

----------------------------------------------
--- pvaServerCreateChannelDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerCreateChannelDecoder (buf, pkt, tree, is_big_endian)
    local cid = getUint64(buf, is_big_endian)
    local sid = getUint64(buf(4), is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fcid, buf(0,4), cid)
    tree:add(fsid, buf(4,4), sid)
    decodeStatus(buf(8), tree, is_big_endian)
end

----------------------------------------------
--- pvaDestroyChannelDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
--- @param cmd the command number
----------------------------------------------
local function pvaDestroyChannelDecoder (buf, pkt, tree, is_big_endian, _)
    local cid = getUint64(buf, is_big_endian)
    local sid = getUint64(buf(4), is_big_endian)
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fsid, buf(0,4), sid)
    tree:add(fcid, buf(4,4), cid)
end

----------------------------------------------
--- pvaClientDestroyDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
--- @param cmd the command number
----------------------------------------------
local function pvaClientDestroyDecoder (buf, pkt, tree, is_big_endian, cmd)
    local command_name = application_messages[cmd]
    local sid = getUint64(buf, is_big_endian)
    local request_id = getUint64(buf, is_big_endian)
    tree:add(fsid, buf(0,4), sid)
    tree:add(frequest_id, buf(4,4), request_id)
    pkt.cols.info:append(string.format("%s(sid=%u, request_id=%u), ", command_name, sid, request_id))
end

----------------------------------------------
--- pvaGenericClientOpDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
--- @param cmd the command number
----------------------------------------------
local function pvaGenericClientOpDecoder (buf, pkt, tree, is_big_endian, cmd)
    local sub_command, request_id, bitset
    request_id, sub_command, buf = decodeSubCommand(buf, pkt, tree, is_big_endian, cmd, true)

    if not buf or buf:len() < 1 then return end
    local pvdbuf = buf:range(0)

    -- if the subcommand is INIT then no change BitSet - just introspect
    if bit.band(sub_command, 0x08) ~= 0 then
        local pvd_tree = tree:add(fpvdi, pvdbuf)
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == RPC_MESSAGE then
        local pvd_tree = tree:add(fpvdi, pvdbuf)
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == PUT_MESSAGE or cmd == PUT_GET_MESSAGE then
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    elseif cmd == MONITOR_MESSAGE then
        -- Monitor messages have a changed bitset
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    else
        buf = decodeStatus(buf, tree, is_big_endian)
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    end

    -- Process remaining payload
    if buf and buf:len() > 0 then
        local pvd_tree = tree:add(fpvd, pvdbuf)
        pvaDecodePVData(buf, pvd_tree, is_big_endian, request_id, bitset)
    end
end


----------------------------------------------
--- pvaGenericServerOpDecoder: decode the given message body into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param tree: the tree node to decode into
--- @param is_big_endian is the byte stream big endian
--- @param cmd the command number
----------------------------------------------
local function pvaGenericServerOpDecoder (buf, pkt, tree, is_big_endian, cmd)
    local sub_command, request_id, bitset
    request_id, sub_command, buf = decodeSubCommand(buf, pkt, tree, is_big_endian, cmd, false)

    if (    cmd ~= MONITOR_UPDATE and
            cmd ~= GET_FIELD_MESSAGE and bit.band(sub_command, 0x08) ~= 0) then
        buf = decodeStatus(buf, tree, is_big_endian)
    end

    if not buf or buf:len() < 1 then return end
    local pvdbuf = buf:range(0)

    -- if the subcommand is INIT then no change BitSet - just introspect
    if bit.band(sub_command, 0x08) ~= 0 then
        -- optional Introspection Data
        local pvd_tree = tree:add(fpvdi, pvdbuf)
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == RPC_MESSAGE then
        buf = decodeStatus(buf, tree, is_big_endian)
        local pvd_tree = tree:add(fpvdi, pvdbuf)
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == MONITOR_MESSAGE then
        -- Monitor messages have a changed bitset
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    elseif cmd == GET_FIELD_MESSAGE then
        local pvd_tree = tree:add(fpvdi, pvdbuf)
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif (cmd == PUT_MESSAGE or
            cmd == PUT_GET_MESSAGE) and buf:len() == 0 then
        return
    else
        buf = decodeStatus(buf, tree, is_big_endian)
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    end

    -- Process remaining payload
    if buf and buf:len() > 0 then
        local pvd_tree = tree:add(fpvd, pvdbuf)
        pvaDecodePVData(buf, pvd_tree, is_big_endian, request_id, bitset)
    end
end

----------------------------------------------
--- server_cmd_handler: the server message command handler mappings
----------------------------------------------
local server_cmd_handler = {
    [BEACON_MESSAGE] =                  pvaServerBeaconDecoder,
    [CONNECTION_VALIDATION_MESSAGE] =   pvsServerValidateDecoder,
    [SEARCH_RESPONSE_MESSAGE] =         pvaServerSearchResponseDecoder,
    [CREATE_CHANNEL_MESSAGE] =          pvaServerCreateChannelDecoder,
    [DESTROY_CHANNEL_MESSAGE] =         pvaDestroyChannelDecoder,
    [GET_MESSAGE] =                     pvaGenericServerOpDecoder,
    [PUT_MESSAGE] =                     pvaGenericServerOpDecoder,
    [PUT_GET_MESSAGE] =                 pvaGenericServerOpDecoder,
    [MONITOR_MESSAGE] =                 pvaGenericServerOpDecoder,
    [GET_FIELD_MESSAGE] =               pvaGenericServerOpDecoder,
    [ARRAY_MESSAGE] =                   pvaGenericServerOpDecoder,
    [RPC_MESSAGE] =                     pvaGenericServerOpDecoder,
}

----------------------------------------------
--- client_cmd_handler: the client message command handler mappings
----------------------------------------------
local client_cmd_handler = {
    [CONNECTION_VALIDATION_MESSAGE] =   pvaClientValidateDecoder,
    [SEARCH_MESSAGE] =                  pvaClientSearchDecoder,
    [CREATE_CHANNEL_MESSAGE] =          pvaClientCreateChannelDecoder,
    [DESTROY_CHANNEL_MESSAGE] =         pvaDestroyChannelDecoder,
    [GET_MESSAGE] =                     pvaGenericClientOpDecoder,
    [PUT_MESSAGE] =                     pvaGenericClientOpDecoder,
    [PUT_GET_MESSAGE] =                 pvaGenericClientOpDecoder,
    [MONITOR_MESSAGE] =                 pvaGenericClientOpDecoder,
    [ARRAY_MESSAGE] =                   pvaGenericClientOpDecoder,
    [DESTROY_REQUEST_MESSAGE] =         pvaClientDestroyDecoder,
    [RPC_MESSAGE] =                     pvaGenericClientOpDecoder,
    [CANCEL_REQUEST_MESSAGE] =          pvaClientDestroyDecoder,
}

----------------------------------------------
--- decode: decode the given buffer into the given packet and root tree node
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param root: the root tree node to decode into
--- @return the number of bytes consumed
----------------------------------------------
local function decode(buf, pkt, root)
    -- minimum of 8 byte header
    if buf:len() < PVA_HEADER_LEN then
        return 0
    end

    -- must start with magic
    local raw_magic = buf(0, 1);
    if raw_magic:uint() ~= PVA_MAGIC
    then
        pkt.cols.info:append("Corrupt message.  Bad magic.")
        return 0;
    end

    -- decode flags
    local raw_flags     = buf(2, 1)
    local flags_val     = raw_flags:uint()
    local is_big_endian = bit.band(flags_val, 0x80)
    local is_ctrl_cmd   = bit.band(flags_val, 0x01)

    -- decode message length
    local message_len = 0
    local raw_len = buf(4, 4)
    if is_ctrl_cmd == 0
    then
        -- decode length with 4 bytes with correct endianness
        message_len = getUint(raw_len, is_big_endian ~= 0)
    end

    -- check that buffer length is long enough
    if buf:len() < PVA_HEADER_LEN + message_len
    then
        return (buf:len() - (PVA_HEADER_LEN + message_len))
    end

    -- decode header
    local header_tree_node = root:add(pva, buf(0, PVA_HEADER_LEN + message_len))

    local raw_cmd = buf(3, 1);
    header_tree_node:add(fmagic,        raw_magic)              -- magic
    header_tree_node:add(fver,          buf(1, 1))              -- protocol version
    local flags = header_tree_node:add(fflags, raw_flags)       -- flags
    if is_ctrl_cmd == 0
    then
        header_tree_node:add(fcmd,      raw_cmd)                -- command
        header_tree_node:add(fsize,     raw_len, message_len)   -- size
    else
        header_tree_node:add(fctrlcmd,  raw_cmd)                -- control command
        header_tree_node:add(fctrldata, raw_len)                -- control data
    end

    -- decode flags
    flags:add(fflag_msgtype,            raw_flags)              -- message type
    flags:add(fflag_segmented,          raw_flags)              -- segmented
    flags:add(fflag_dir,                raw_flags)              -- direction
    flags:add(fflag_end,                raw_flags)              -- endianness

    -- decode command op code
    local cmd = raw_cmd:uint()
    local show_generic_cmd = 1

    buf = buf(PVA_HEADER_LEN, message_len);
    if is_ctrl_cmd == 0
    then
        -- application message
        if bit.band(flags_val, 0x40) ~= 0
        then
            -- server
            local cmd_handler = server_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(buf, pkt, header_tree_node, is_big_endian ~= 0, cmd)
                show_generic_cmd = 0
            end
        else
            -- client
            local cmd_handler = client_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(buf, pkt, header_tree_node, is_big_endian ~= 0, cmd)
                show_generic_cmd = 0
            end
        end
    else
        -- control message
        local cmd_name = control_messages[cmd]
        if cmd_name
        then
            pkt.cols.info:append(cmd_name .. ", ")
        else
            pkt.cols.info:append("Msg: " .. cmd .. " ")
        end
        show_generic_cmd = 0
    end

    if show_generic_cmd ~= 0
    then
        local cmd_name = application_messages[cmd]
        if cmd_name
        then
            pkt.cols.info:append(cmd_name .. ", ")
        else
            pkt.cols.info:append("Msg: " .. cmd .. " ")
        end

        if message_len <= 0 then return PVA_HEADER_LEN + message_len end

        if is_big_endian
        then
            header_tree_node:add(fpvd, buf(0, message_len))
        else
            header_tree_node:addle(fpvd, buf(0, message_len))
        end
    end

    return PVA_HEADER_LEN + message_len
end

----------------------------------------------
--- dissector: the dissector function
--- Implementation of the PVA disector
----------------------------------------------
--- @param buf: the buffer to decode from
--- @param pkt: the packet to decode into
--- @param root: the root tree node to decode into
----------------------------------------------
function pva.dissector (buf, pkt, root)
    -- must start with magic
    local raw_magic = buf(0, 1);
    if raw_magic:uint() ~= PVA_MAGIC
    then
        return
    end

    -- set protocol name in protocol column
    pkt.cols.protocol = pva.name

    -- set up initial part of info column
    pkt.cols.info:clear()
    pkt.cols.info:append(pkt.src_port .. " -> " .. pkt.dst_port .. " ")
    if bit.band(buf(2, 1):uint(), 0x40) ~= 0
    then
        pkt.cols.info:append("Server ")
    else
        pkt.cols.info:append("Client ")
    end

    local total_consumed = 0

    while buf:len() > 0
    do
        local consumed = decode(buf, pkt, root)
        consumed = not consumed and total_consumed or math.floor(consumed)

        if consumed < 0
        then
            -- overrun
            pkt.desegment_offset = total_consumed
            pkt.desegment_len = -consumed
            return
        elseif consumed < PVA_HEADER_LEN
        then
            -- incomplete
            pkt.cols.info:preppend("[Incomplete] ")
            break
        else
            -- just right
            total_consumed = total_consumed + consumed
            buf = buf(consumed):tvb()
        end
    end
end

local function test_pva (buf, pkt, root)
    if buf:len()<PVA_HEADER_LEN or buf(0,1):uint()~= PVA_MAGIC or buf(1,1):uint()==0 or not application_messages[buf(3,1):uint()]
    then
        return false
    end
    pva.dissector(buf, pkt, root)
    pkt.conversation = pva
    return true
end

-- initialise
local utbl = DissectorTable.get("udp.port")
utbl:add(5075, pva)
utbl:add(5076, pva)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5075, pva)
DissectorTable.get("tls.alpn"):add("pva/1", pva)

local status, err = pcall(function() pva:register_heuristic("tcp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic TCP dissector.  Must manually specify TCP port! (try newer wireshark?)")
    print(err)
end

status, err = pcall(function() pva:register_heuristic("udp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic UDP dissector.  Must manually specify UDP port! (try newer wireshark?)")
    print(err)
end

io.stderr:write("Loaded PVA\n")
