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

local placeholder   = ProtoField.bytes("pva.placeholder", " ")

----------------------------------------------
-- Magic, Version, Flags, Command, Control Command, Control Data, Size, Body, PVData, GUID
----------------------------------------------

local fmagic        = ProtoField.uint8(     "pva.magic",        "Magic",            base.HEX)
local fver          = ProtoField.uint8(     "pva.version",      "Version",          base.DEC)
local fflags        = ProtoField.uint8(     "pva.flags",        "Flags",            base.HEX)
local fflag_dir     = ProtoField.uint8(     "pva.direction",    "Direction",
        base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end     = ProtoField.uint8(     "pva.endian",       "Byte order",
        base.HEX, {[0]="LSB",[1]="MSB"}, 0x80)
local fflag_msgtype = ProtoField.uint8(     "pva.msg_type",     "Message type",
        base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented = ProtoField.uint8(   "pva.segmented",    "Segmented",
        base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd          = ProtoField.uint8(     "pva.command",      "Command",
        base.HEX, application_messages)
local fctrlcmd      = ProtoField.uint8(     "pva.ctrlcommand",  "Control Command",
        base.HEX, control_messages)
local fctrldata     = ProtoField.uint32(    "pva.ctrldata",     "Control Data",     base.HEX)
local fsize         = ProtoField.uint32(    "pva.size",         "Size",             base.DEC)
local fbody         = ProtoField.bytes(     "pva.body",         "Body")
local fpvd          = ProtoField.bytes(     "pva.pvd",          "PVData Body")
local fguid         = ProtoField.bytes(     "pva.guid",         "GUID")

----------------------------------------------
-- PVData Fields
----------------------------------------------

local fpvd_field_name    = ProtoField.string(   "pva.pvd_field_name",       "Field Name")
local fpvd_type          = ProtoField.uint8(    "pva.pvd_type",             "Type Code",   base.HEX)
local fpvd_type_id       = ProtoField.uint16(   "pva.pvd_type_id",          "Type ID")

local fpvd_struct        = ProtoField.bytes(    "pva.pvd_struct",           "PVStructure")
local fpvd_field         = ProtoField.bytes(    "pva.pvd_field",            "Field")
local fpvd_value         = ProtoField.bytes(    "pva.pvd_value",            "Value")

local fpvd_debug         = ProtoField.bytes(    "pva.pvd_debug",            "Debug Info")

----------------------------------------------
-- Common Fields
----------------------------------------------

local fcid          = ProtoField.uint32(    "pva.cid",          "Client Channel ID")
local fsid          = ProtoField.uint32(    "pva.sid",          "Server Channel ID")
local frequest_id         = ProtoField.uint32(    "pva.request_id",         "Operation ID")
local fsubcmd       = ProtoField.uint8(     "pva.subcmd",       "Sub-command",      base.HEX)
local fsubcmd_proc  = ProtoField.uint8(     "pva.process",      "Process",          base.HEX, {[0]="",[1]="Yes"}, 0x04)
local fsubcmd_init  = ProtoField.uint8(     "pva.init",         "Init   ",          base.HEX, {[0]="",[1]="Yes"}, 0x08)
local fsubcmd_dstr  = ProtoField.uint8(     "pva.destroy",      "Destroy",          base.HEX, {[0]="",[1]="Yes"}, 0x10)
local fsubcmd_get   = ProtoField.uint8(     "pva.get",          "Get    ",          base.HEX, {[0]="",[1]="Yes"}, 0x40)
local fsubcmd_gtpt  = ProtoField.uint8(     "pva.getput",       "GetPut ",          base.HEX, {[0]="",[1]="Yes"}, 0x80)
local fstatus       = ProtoField.uint8(     "pva.status",       "Status",           base.HEX, status_codes)

----------------------------------------------
-- BEACON
----------------------------------------------

local fbeacon_seq = ProtoField.uint8("pva.bseq", "Beacon sequence#")
local fbeacon_change = ProtoField.uint16("pva.change", "Beacon change count")

-- For CONNECTION_VALIDATION

local fvalid_bsize  = ProtoField.uint32(    "pva.qsize",        "Client Queue Size")
local fvalid_isize  = ProtoField.uint16(    "pva.isize",        "Client Introspection registery size")
local fvalid_qos    = ProtoField.uint16(    "pva.qos",          "Client QoS",   base.HEX)
local fvalid_method = ProtoField.string(    "pva.method",       "AuthZ method")
local fvalid_azflg  = ProtoField.uint8 (    "pva.authzflag",    "AuthZ Flags",  base.HEX)
local fvalid_azcnt  = ProtoField.uint8 (    "pva.authzcnt",     "AuthZ Elem‑cnt", base.DEC)

-- For AUTHZ_REQUEST

local fauthz_request = ProtoField.string(   "pva.authzrequest", "AuthZ request")
local fvalid_host   = ProtoField.string(    "pva.host",         "AuthZ host")
local fvalid_authority = ProtoField.string( "pva.authority",    "AuthZ authority")
local fvalid_user   = ProtoField.string(    "pva.user",         "AuthZ name")
local fvalid_account = ProtoField.string(   "pva.account",      "AuthZ account")
local fvalid_isTLS  = ProtoField.uint8(     "pva.isTLS",        "AuthZ isTLS")

-- For AUTHZ_RESPONSE

local fauthz_response = ProtoField.string("pva.authzresponse",  "AuthZ response")

-- For AuthZ Entry Array (removed fauth_entry_index as no longer needed)

-- For SEARCH
local fsearch_seq   = ProtoField.uint32(    "pva.seq",          "Search Sequence #")
local fsearch_addr  = ProtoField.bytes(     "pva.addr",          "Address")
local fsearch_port  = ProtoField.uint16(    "pva.port",         "Port")
local fsearch_mask  = ProtoField.uint8(     "pva.mask",         "Mask",         base.HEX)
local fsearch_mask_repl  = ProtoField.uint8("pva.reply",        "Reply",        base.HEX, {[0]="Optional",[1]="Required"}, 0x01)
local fsearch_mask_bcast = ProtoField.uint8("pva.ucast",        "Reply",        base.HEX, {[0]="Broadcast",[1]="Unicast"}, 0x80)
local fsearch_proto = ProtoField.string(    "pva.proto",        "Transport Protocol")
local fsearch_count = ProtoField.uint16(    "pva.count",        "PV Count")
local fsearch_cid   = ProtoField.uint32(    "pva.cid",          "CID")
local fsearch_name  = ProtoField.string(    "pva.pv",           "Name")

-- For SEARCH_RESPONSE
local fsearch_found = ProtoField.bool(      "pva.found",        "Found")

----------------------------------------------
-- ProtoFields variables
----------------------------------------------

pva.fields = {
    placeholder, fmagic, fver, fflags, fflag_dir, fflag_end, fflag_msgtype, fflag_segmented, fcmd, fctrlcmd, fctrldata, fsize, fbody, fpvd, fguid,
    fcid, fsid, frequest_id, fsubcmd, fsubcmd_proc, fsubcmd_init, fsubcmd_dstr, fsubcmd_get, fsubcmd_gtpt, fstatus,
    fbeacon_seq, fbeacon_change,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_host, fvalid_method, fvalid_authority, fvalid_account, fvalid_user, fvalid_isTLS,
    fvalid_azflg, fvalid_azcnt, fauthz_request, fauthz_response,
    fpvd_struct, fpvd_field, fpvd_field_name, fpvd_type, fpvd_value, fpvd_type_id, fpvd_debug,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_mask_repl, fsearch_mask_bcast,
    fsearch_proto, fsearch_count, fsearch_cid, fsearch_name,
    fsearch_found,
}

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

----------------------------------------------
-- Introspection (PVData) encoding types
-- Used to determine the type before reading data
----------------------------------------------

local TYPE_CODE_NULL = 0xFF;           -- NULL_TYPE: null field
local TYPE_CODE_ONLY_ID = 0xFE;        -- ONLY_ID: 0xFE + ID (2 bytes)
local TYPE_CODE_FULL_WITH_ID = 0xFD;   -- FULL_WITH_ID: 0xFD + ID (2 bytes) + FieldDesc
local TYPE_CODE_TAGGED_ID = 0xFC;      -- FULL_TAGGED_ID: 0xFC + ID (2 bytes) + tag [ Undecoded in this lua ]
local TYPE_CODE_RAW = 0xDF;            -- FieldDesc

----------------------------------------------
-- Utility functions
----------------------------------------------

-- FieldDesc first discriminator

function isNull(type_code)
    return type_code == TYPE_CODE_NULL
end

function isOnlyId(type_code)
    return type_code == TYPE_CODE_ONLY_ID
end

function isFullWithId(type_code)
    return type_code == TYPE_CODE_FULL_WITH_ID
end

function isFullTaggedWithId(type_code)
    return type_code == FULL_TAGGED_ID_TYPE_CODE
end

function isFull(type_code)
    return type_code < TYPE_CODE_RAW
end

-- Kind
function isBoolType(type_code)
    return bit.band(type_code, 0xE0) == 0x00
end

function isIntType(type_code)
    return bit.band(type_code, 0xE0) == 0x20
end

function isFloatType(type_code)
    return bit.band(type_code, 0xE0) == 0x40
end

function isStringType(type_code)
    return bit.band(type_code, 0xE0) == 0x60
end

function isComplexType(type_code)
    return bit.band(type_code, 0xE0) == 0x80
end

-- Array Type
function isArrayType(type_code)
    return bit.band(type_code, 0x18) ~= 0
end

function isVariableArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x08
end

function isBoundedArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x10
end

function isFixedArrayType(type_code)
    return bit.band(type_code, 0x18) == 0x18
end

-- Kind Details


function getIntLen(type_code)
    local b = bit.band(type_code, 0x06)
    if b == 0x00 then
        return 8
    elseif b == 0x00 then
        return 16
    elseif b == 0x00 then
        return 32
    else
        return 64
    end
end

function isIntSigned(type_code)
    return bit.band(type_code, 0x01) == 0
end

function getIntName(type_code)
    if isIntSigned(type_code) then
        return "int" .. getIntLen(type_code) .. "_t"
    else
        return "uint" .. getIntLen(type_code) .. "_t"
    end
end

function getFloatLen(type_code)
    if bit.band(type_code, 0x07) == 2 then
        return 32
    else
        return 64
    end
end

function getFloatName(type_code)
    if bit.band(type_code, 0x07) == 2 then
        return "float"
    else
        return "double"
    end
end

function getComplexName(type_code)
    local b = bit.band(type_code, 0x07)
    if b == 0x00 then
        return "struct"
    elseif b == 0x01 then
        return "union"
    elseif b == 0x02 then
        return "any"
    else
        return "fixed_string"
    end
end

function getTypeName(type_code)
    if isBoolType(type_code) then
        return "bool"
    elseif isIntType(type_code) then
        return getIntName(type_code)
    elseif isFloatType(type_code) then
        return getFloatName(type_code)
    elseif isStringType(type_code) then
        return "string"
    else
        return getComplexName(type_code)
    end
end

function getFullTypeName(type_code)
    local a = ""
    if isArrayType(type_code) then
        a="[]"
    end
    return getTypeName(type_code) .. a
end

--- Format field name and type for display in protocol tree
---
--- @param type_code number the field type code
--- @param field_name string the name of the field, defaults to value if not specified
--- @param type_name string the optional "Type ID" or Normative Type string to use for complex types
--- @return string the formatted field name and type
function formatField(type_code, field_name, type_name)
    local a = ""
    if isArrayType(type_code) then
        a="[]"
    end

    field_name = field_name or "value"
    type_name = type_name or getTypeName(type_code)
    local nt = nt_types[type_name]
    if nt then
        type_name = nt
    end

    return string.format("%s%s (0x%02X: %s%s)", field_name, a, type_code, type_name, a)
end

----------------------------------------------
-- The Operation ID PVField Cache
----------------------------------------------

--- The Field Registry
--- @field roots table this is a map of roots keyed on request_id
--- @field data table this is the map of Field-maps keyed on request_id, each sub-map is keyed on field_id
local FieldRegistry = {}

-- Initialize the Field Registry
FieldRegistry.data = {}
FieldRegistry.roots = {}

function FieldRegistry:getRootField(request_id)
    return self.roots[request_id]
end

--- Create a new `Field`
---
--- - If the `type` name is specified then it is used as the type name of this `Field`.
---
--- - If `parent_field` is specified then the newly created `Field` is added as a child of the parent `Field`.
---   It is up to the caller to assure that the parent is of the appropriate type to accept children.
---
--- @param name string the field name
--- @param type_code number the type code
--- @param type string the string name to use as the type
--- @param len number optional number of elements in a fixed or bounded array
--- @param parent_field table the optional parent of this field
function FieldRegistry:createField(name, type_code, type, len, parent_field)
    -- Determine the type string
    local type_string = type or getFullTypeName(type_code)

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

--- Create a new `Field` and add it to the `FieldRegistry` if `request_id` and `field_id` are specified
---
--- - If `request_id` and  `field_id` are provided then new `Field` is added to the `FieldRegistry` .
--- @param name string the field name
--- @param type_code number the type code
--- @param type string the string name to use as the type
--- @param len number optional number of elements in a fixed or bounded array
--- @param parent_field table the optional parent of this field, nil to specify a root Field
--- @param request_id number the storage of fields in the `FieldRegistry` is partitioned by `request_id`
--- @param field_id number the identifier of a `Field` specified in the PVAccess protocol
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

--- Get a Field from the Field Registry
--- Retrieves a Field identified by the given field_id from the given request_id partition of the Field Registry
function FieldRegistry:getField(request_id, field_id)
    return request_id and field_id and self.data and self.data[request_id] and self.data[request_id][field_id]
end

--- Get sub-fields of the given Field
--- @param field table the parent Field to get the sub-Fields of
function FieldRegistry:getSubFields(field)
    return field.sub_fields
end

--- Get all fields for a request_id
function FieldRegistry:getFields(request_id)
    return self.data[request_id] or {}
end

--- Get a field by depth-first index within an request_id
--- - Starts at the root of a request_id and traverses the field graph depth first.
--- - It indexes fields it finds from 0 (root)
--- List of Fields, ... can be used to reconstruct tree for display
--- @param request_id number the request_id to search in
--- @param index number the zero-based index of the field to retrieve
--- @return table a List of Fields from the root to the found field
function FieldRegistry:getIndexedField(request_id, index)
    local root_field = self.roots[request_id]

    if not root_field then
        return nil
    end

    --- search from the given field down depth first, recursing when necessary
    --- @return table a List of Fields from the root to the found field
    --- @return number remaining indices space to search
    local function depthFirstTraverse(field, target_index)
        local field_info = {
            name = field.name,
            type_code = field.type_code,
            type = field.type,
            len = field.len,
            tree = nil -- to be used later when the fields are displayed
        }

        -- is this field the target field
        if target_index == 0 then
            return { field_path }, 0
        end
        target_index = target_index - 1

        -- If we have any sub fields then check them
        for _, sub_field in ipairs(field.sub_fields) do
            local sub_field_path
            sub_field_path, target_index = depthFirstTraverse(sub_field, target_index)
            if target_index == 0 and sub_field_path then
                table.insert(sub_field_path, 1, field_info)
                return sub_field_path, 0
            end
        end

        return nil, target_index

    end

    local field_path, final_index = depthFirstTraverse(root_field, index)
    if final_index == 0 then
        return field_path
    else
        return nil
    end
end

----------------------------------------------
--- bufToBinary: get an binary string of digits from buffer
--- @param buf table to read the bytes from
----------------------------------------------
function bufToBinary(buf)
    if not buf or buf:len() == 0 then
        return ""
    end

    local result = {}
    local bytes = buf:bytes()

    for i = 0, bytes:len() - 1 do
        local byte = bytes:get_index(i)
        local binary_byte = ""

        -- Convert each byte to 8-bit binary
        for bit = 7, 0, -1 do
            binary_byte = binary_byte .. ((byte >> bit) & 1)
        end

        result[#result + 1] = binary_byte
    end

    return table.concat(result)
end

----------------------------------------------
--- getUint: get an unsigned integer with the correct byte order
--- @param buf table to read the uint from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getUint(buf, is_big_endian)
    if buf:len() == 1 then
        return buf:byte()
    end
    if is_big_endian == nil or is_big_endian then
        if buf:len() == 2 then
            return buf:uint()
        else
            return buf:uint64():tonumber()
        end
    else
        if buf:len() == 2 then
            return buf:le_uint()
        else
            return buf:le_uint64():tonumber()
        end
    end
end

----------------------------------------------
--- getInt: get an integer with the correct byte order
--- @param buf table to read the int from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getInt(buf, is_big_endian)
    if buf:len() == 1 then
        return buf:byte()
    end
    if is_big_endian == nil or is_big_endian then
        if buf:len() == 2 then
            return buf:int()
        else
            return buf:int64():tonumber()
        end
    else
        if buf:len() == 2 then
            return buf:le_int()
        else
            return buf:le_int64():tonumber()
        end
    end
end

----------------------------------------------
--- getUintForDisplay: get an unsigned integer formatted for display (avoiding .0 suffix)
--- @param buf table to read the uint from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getUintForDisplay(buf, is_big_endian)
    if buf:len() == 1 then
        return tostring(buf:byte())
    end
    if is_big_endian == nil or is_big_endian then
        if buf:len() == 2 then
            return tostring(buf:uint())
        else
            return tostring(buf:uint64())
        end
    else
        if buf:len() == 2 then
            return tostring(buf:le_uint())
        else
            return tostring(buf:le_uint64())
        end
    end
end

----------------------------------------------
--- getIntForDisplay: get an integer formatted for display (avoiding .0 suffix)
--- @param buf table to read the int from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getIntForDisplay(buf, is_big_endian)
    if buf:len() == 1 then
        return tostring(buf:byte())
    end
    if is_big_endian == nil or is_big_endian then
        if buf:len() == 2 then
            return tostring(buf:int())
        else
            return tostring(buf:int64())
        end
    else
        if buf:len() == 2 then
            return tostring(buf:le_int())
        else
            return tostring(buf:le_int64())
        end
    end
end

----------------------------------------------
--- getFloat: get a float with the correct byte order
--- @param buf table to read the float from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getFloat(buf, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return buf:float()
    else
        return buf:le_float()
    end
end

----------------------------------------------
--- getDouble: get a double with the correct byte order
--- @param buf table to read the double from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getDouble(buf, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return buf:float()  -- Wireshark's float() method handles both 32-bit and 64-bit
    else
        return buf:le_float()  -- Wireshark's le_float() method handles both 32-bit and 64-bit
    end
end

----------------------------------------------
--- getUint32: get an unsigned 32-bit integer with the correct byte order
--- @param buf table to read the int64 from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getUint32(buf, is_big_endian)
    return getUint(buf(0,2), is_big_endian)
end

----------------------------------------------
--- getUint64: get an unsigned 64-bit integer with the correct byte order
--- @param buf table to read the int64 from
--- @param is_big_endian boolean flag to indicate the bigendian-ness
----------------------------------------------
local function getUint64(buf, is_big_endian)
    return getUint(buf(0,4), is_big_endian)
end


-----------------------------------------------
--- decodeSize: decode a size from a TvbRange buffer using 3-tier encoding
---
--- Tier 1: 1 byte (0x00-0xFE) → value 0-254
--- Tier 2: 5 bytes (0xFF + 4-byte signed int32) → value 255-2^31-2
--- Tier 3: 13 bytes (0xFF + 0x7FFFFFFF + 8-byte signed int64) → value 2^31-1 to 2^63-1
---
--- @param buf table whose first byte is the Size
--- @param is_big_endian boolean flag to indicate the bigendian-ness
--- @return number size
--- @return table remaining buffer
-----------------------------------------------------------------
local function decodeSize(buf, is_big_endian)

    -- 1. fast path: single‑byte size 0‑254
    local first = buf:range(0,1):uint()      -- one byte
    if first < 0xFF then
        if buf:len() > 1 then
            return first, buf:range(1)       -- drop 1 byte
        else
            return first, nil                -- nothing remains after dropping a byte
        end
    end

    -- 2. extended 32‑bit form (5 bytes total)
    local v32 = (is_big_endian and
            buf:range(1,4):int()  or    -- signed BE int32
            buf:range(1,4):le_int())    -- signed LE int32

    if v32 ~= 0x7FFFFFFF then                -- ordinary 32‑bit size
        assert(v32 >= 0, "negative size")
        return v32, buf:range(5)             -- drop 5 bytes
    end

    -- 3. extended 64‑bit form (13 bytes total)
    local v64 = (is_big_endian and
            buf:range(5,8):int64()  or  -- signed BE int64 (Int64 obj)
            buf:range(5,8):le_int64())  -- signed LE int64
    assert(v64:tonumber() >= 0, "negative size")

    return v64, buf:range(13)                -- drop 13 bytes
end

-- take the next byte as a count, followed by that many bytes of the bitset
local function getBitSet(buf, is_big_endian)
    local bitset_count
    bitset_count, buf = decodeSize(buf, is_big_endian)
    if buf:len() < bitset_count then
        return nil, nil
    elseif buf:len() == bitset_count then
        return buf, nil
    else
        return buf:range(0, bitset_count), buf:range(bitset_count)
    end
end

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

    if buf:len() > 1 then
        buf = buf:range(1)
    else
        buf = nil
    end

    return type_code, buf
end


----------------------------------------------
-- decodeString: extract a string and return that string, and the remaining buffer
-- string is encoded as a size followed by the actual string
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @return the string and the remaining buffer
local function decodeString(buf, is_big_endian)
    if not buf or buf:len() == 0 then
        return nil, buf
    end

    local len, remaining_buf = decodeSize(buf, is_big_endian)
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

--- get the string representation of the data pointed to by buf
--- @param buf table the buffer to read from
--- @param is_big_endian boolean endianness
--- @param type_code number the type code
--- @return string the string representation of the data
--- @return number the number of bytes the data took on the wire
function getDataForType(buf, is_big_endian, type_code)
    -- only for bool, int, float, and string scalars
    local value = ""
    local size = 1

    if isStringType(type_code) then
        local remaining_buf
        value, remaining_buf = decodeString(buf, is_big_endian)
        size = buf:len() - remaining_buf:len()
    else
        if isBoolType(type_code) then
            value = toString(buf(0,1):uint() ~= 0)

        elseif isIntType(type_code) then
            local the_int
            local signed = isIntSigned(type_code)
            size = getIntLen(type_code) / 8
            if is_big_endian then
                if signed then the_int = buf(0,size):int() else the_int = buf(0,size):uint() end
            else
                if signed then the_int = buf(0,size):le_int() else the_int = buf(0,size):le_uint() end
            end
            value = toString(the_int)

        elseif isFloatType(type_code) then
            local the_float
            size = getFloatLen(type_code) / 8
            if is_big_endian then the_float = buf(0,size):float() else the_float = buf(0,size):le_float() end
            value = toString(the_float)

        end
    end

    return value, size
end

function displayDataForType(buf, is_big_endian, type_code, tree, label, len)
    -- only for non complex types
    local value
    local size = 0
    if not isArrayType(type_code) then
        -- scalar
        value, size = getDataForType(buf, is_big_endian, type_code)
        tree:add(buf(0, size), string.format(label .. ": %s", value))
    else
        -- get count
        if isVariableArrayType(type_code) or isBoundedArrayType(type_code) then
            -- read len
            local ar_buf
            len, ar_buf = decodeSize(buf, is_big_endian)
        end

        -- loop over data
        for i = 0, len - 1 do
            -- display
            local el_size
            local el_label = label .. "[" .. i .. "]"
            value, el_size = getDataForType(ar_buf, is_big_endian, type_code)
            tree:add(ar_buf(0, size), string.format(el_label .. ": %s", value))
            ar_buf:range(el_size)
            size = size + el_size
        end
    end

    return buf:range(size)
end


local function pvaDecodeIntrospectionData(buf, tree, is_big_endian, request_id, name, parent_field)
    -- no status for clients, just the optional Introspection Data
    local type_code
    type_code, buf = pvaDecodeTypeCode(buf, tree)

    if not buf or buf:len() == 0 or isNull(type_code) then
        return nil
    end

    local field_id, tag, len, field_desc, field

    local is_id = isOnlyId(type_code)
    local is_f = isFull(type_code)
    local is_f_id = isFullWithId(type_code)
    local is_ft_id = isFullTaggedWithId(type_code)

    if is_f_id or is_ft_id or is_id then
        -- get ID
        field_id = getUint32(buf, is_big_endian)
        tree:add(buf(0, 2), string.format("Cached Field ID: (0x%04X)", field_id))
        buf = buf:range(2)
    end

    if is_ft_id then
        -- get tag
        local tag_buf = buf
        tag, buf = decodeSize(buf, is_big_endian)
        tree:add(tag_buf(0, tag_buf:len() - buf:len()), string.format("Cached Tag ID: %d", tag))
    end

    if is_id then
        -- retrieve from registry
        field = FieldRegistry:getField(request_id, field_id)
    end

    if is_f or is_f_id or is_ft_id then
        if is_f then
            -- use this type_code as a raw field desc
            field_desc = type_code
        elseif is_f_id or is_ft_id then
            -- get field_desc code
            field_desc = buf(0,1):uint()
            buf = buf:range(1)

            local is_foba_id = isFixedArrayType(field_desc) or isBoundedArrayType(field_desc)

            if is_foba_id then
                -- get array len/bounds
                local len_buf = buf
                len, buf = decodeSize(buf, is_big_endian)
                tree:add(len_buf(0, len_buf:len() - buf:len()), string.format("Array Len/Bounds: %d", len))
            end
        end

        if isComplexType(field_desc) then
            -- read type id
            local type_id
            local type_id_buf = buf
            type_id, buf = decodeString(buf, is_big_endian)

            -- now make the field with the type id
            field = FieldRegistry:addField(name, field_desc, type_id, len, parent_field, request_id, field_id)
            local range = type_id_buf(0, type_id_buf:len() - buf:len())
            local sub_tree = tree:add(range, formatField(field.type_code, field.name, field.type))

            -- get field count
            local count
            count, buf = decodeSize(buf, is_big_endian)

            for i = 1, count do
                local sub_field_name
                sub_field_name, buf = decodeString(buf, is_big_endian)
                if not buf then return nil, nil end

                -- Sub-fields in a struct are regular field definitions
                _, buf = pvaDecodeIntrospectionData(buf, sub_tree, is_big_endian, request_id, sub_field_name, field)
            end
        else
            -- no type id, make the field
            field = FieldRegistry:addField(name, field_desc, nil, len, parent_field, request_id, field_id)
            local range = buf(0, 1)
            tree:add(range, formatField(field.type_code, field.name, field.type))
        end
    end

    return field, buf
end

--- Decode the introspection data into a tree representing the data structure
---
--- Type Code determines how this field is processed.
--- - TYPE_CODE_NULL         - There is no data to be decoded, or displayed, for this field
--- - TYPE_CODE_ONLY_ID      - Only an ID follows (two bytes)
--- - TYPE_CODE_FULL_WITH_ID - ID (two bytes) + FieldDesc
--- - TYPE_CODE_TAGGED_ID    - ID (two bytes) + tag + FieldDesc [UNSUPPORTED]
--- - TYPE_CODE_RAW          - FieldDesc
---
--- @param buf any message to decode
--- @param tree any the root tree not to attach the decoded data to
--- @param is_big_endian boolean is the data to be decoded big-endian
--- @param request_id number this is the request id to be used to store the full introspection data against
--- @param type_code number the type of introspection
--- @param raw_field_desc any if this is a rew field desc then this is the start of the raw FieldDesc buf
---
local function pvaDecodePVDataType(buf, tree, is_big_endian, request_id)
    local field, data_buf
    field, data_buf = pvaDecodeIntrospectionData(buf, tree, is_big_endian, request_id)
    if not field then return end
end

-- decode sub command
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
-- skipNextElement: skip the next element and return the remaining buffer
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @return the remaining buffer
----------------------------------------------
local function skipNextElement(buf, is_big_endian)
    local len, remaining_buf = decodeSize(buf, is_big_endian)
    if len == remaining_buf:len() then
        return nil
    else
        return remaining_buf(len + 1)
    end
end

----------------------------
-- PVData decoders
----------------------------

-- EPICS timestamp conversion to human readable format
local function formatEpicsTimestamp(seconds, nanoseconds)
    -- EPICS epoch is January 1, 1990 00:00:00 UTC
    -- Unix epoch is January 1, 1970 00:00:00 UTC
    -- Difference: 631152000 seconds (20 years)
    local unix_seconds = seconds + 631152000
    local date_str = os.date("!%Y-%m-%d %H:%M:%S", unix_seconds)
    return string.format("%s.%09d UTC", date_str, nanoseconds)
end

-- Enhanced alarm status decoder
local function decodeAlarmStatus(severity, status)
    local severity_names = {
        [0] = "NO_ALARM",
        [1] = "MINOR",
        [2] = "MAJOR",
        [3] = "INVALID"
    }

    local status_names = {
        [0] = "NO_ALARM",
        [1] = "READ",
        [2] = "WRITE",
        [3] = "HIHI",
        [4] = "HIGH",
        [5] = "LOLO",
        [6] = "LOW",
        [7] = "STATE",
        [8] = "COS",
        [9] = "COMM",
        [10] = "TIMEOUT",
        [11] = "HWLIMIT",
        [12] = "CALC",
        [13] = "SCAN",
        [14] = "LINK",
        [15] = "SOFT",
        [16] = "BAD_SUB",
        [17] = "UDF",
        [18] = "DISABLE",
        [19] = "SIMM",
        [20] = "READ_ACCESS",
        [21] = "WRITE_ACCESS"
    }

    local sev_name = severity_names[severity] or string.format("UNKNOWN(%d)", severity)
    local stat_name = status_names[status] or string.format("UNKNOWN(%d)", status)

    return sev_name, stat_name
end

-- Helper function to get type size (simplified version)
local function getTypeSize(type_code)
    if type_code == TYPE_CODE_BOOLEAN then return 1 -- bool
    elseif type_code == TYPE_CODE_BYTE then return 1 -- int8_t
    elseif type_code == TYPE_CODE_SHORT then return 2 -- int16_t
    elseif type_code == TYPE_CODE_INT then return 4 -- int32_t
    elseif type_code == TYPE_CODE_LONG then return 8 -- int64_t
    elseif type_code == TYPE_CODE_UBYTE then return 1 -- uint8_t
    elseif type_code == TYPE_CODE_USHORT then return 2 -- uint16_t
    elseif type_code == TYPE_CODE_UINT then return 4 -- uint32_t
    elseif type_code == TYPE_CODE_ULONG then return 8 -- uint64_t
    elseif type_code == TYPE_CODE_FLOAT then return 4 -- float
    elseif type_code == TYPE_CODE_DOUBLE then return 8 -- double
    else return 0 -- variable length or unknown
    end
end

-- Helper function to identify authentication method strings
local function isAuthMethod(method_name, prev_was_method)
    if not method_name then
        return false
    end

    -- Handle both TvbRange and string types
    local method_str
    if type(method_name) == "string" then
        method_str = method_name
    else
        method_str = method_name:string()
    end

    local lower_case_method_name = method_str:lower()

    -- Strong method indicators
    local strong_methods = {"x509", "ca"}
    for _, method in ipairs(strong_methods) do
        if lower_case_method_name == method then
            return true
        end
    end

    -- "anonymous" is typically a username unless it's clearly in method position
    if lower_case_method_name == "anonymous" then
        -- Treat as method only if we've already seen a method (meaning this starts a new entry)
        return prev_was_method
    end

    return false
end

----------------------------------------------
-- decodeStatus: decode the given message body to extract the status
-- @param buf: the buffer to decode from
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function decodeStatus (buf, tree, is_big_endian)
    local status_code = buf(0,1):uint()
    local sub_tree = tree:add(fstatus, buf(0,1))
    if buf:len()>1 then
        buf = buf(1)
    end

    if status_code ==0xFF then
        return buf
    else
        local message, stack
        message, buf = decodeString(buf, is_big_endian)
        stack, buf = decodeString(buf, is_big_endian)
        sub_tree:append_text(message:string())
        if(status_code ~=0 and stack:len()>0)
        then
            sub_tree:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
        end
        return buf
    end
end

function displayFieldPath(buf, root_tree, is_big_endian, field_path, last_field_path)
    -- start from top
    local pos = 1
    local current_tree = root_tree

    -- find starting position
    if last_field_path then
        -- copy tree's from last to current until we diverge
        for i = 1, math.min(#last_field_path, #field_path) do
            local last = last_field_path[i]
            local current = field_path[i]

            -- copy tree
            current.tree = last.tree

            if last.name ~= current.name then
                -- we diverged
                pos = i
                current_tree = last.tree
                break
            end
        end
    end

    -- Loop over remaining nodes to leaf
    for i = pos, #field_path do
        local current = field_path[i]
        current.tree = current_tree -- set tree for this field

        local field_label = formatField(current.type_code, current.name, current.type)

        if isComplexType(current.type_code) then
            -- just show the label as this is the complex type
            -- create a new tree and continue
            current_tree = current_tree:add(field_label)
        else
            -- this is a leaf node so need to show data
            buf = displayDataForType(buf, is_big_endian, type_code, current_tree, field_label, current.len)
        end
    end
end

function decodePVField(buf, root_tree, is_big_endian, request_id, bitset_str)
    if bitset_str then
        -- Look up the root field from the cache
        local root_field = FieldRegistry:getRootField(request_id)
        local bit_count = bitset_str:len()

        local last_field_path = nil

        -- loop over bits
        for index=0, bit_count -1 do
            local bit = bitset_str:sub(bit_count-index, bit_count-index)
            if bit == "1" then
                -- get the field path (starting from the root)

                local field_path = FieldRegistry:getIndexedField(request_id, index)
                if not field_path then return end

                -- display this field
                last_field_path = displayFieldPath(buf, root_tree, is_big_endian, field_path, last_field_path)
            end
        end
    end
end

-- Parse PVData
function pvaDecodePVData(buf, tree, is_big_endian, request_id, bitset)
    local bitset_str
    if bitset then
        bitset_str = bufToBinary(bitset)
        tree:add(bitset, string.format("Changed BitSet (%d bytes): %s", bitset:len(), bitset_str))
    end

    decodePVField(buf, tree, is_big_endian, request_id, bitset_str)
end

-- Format field type for display
function formatFieldType(field)
    if not field or not field.type_code then
        return "unknown"
    end

    return string.format("0x%02x: %s", field.type_code, field.type or "unknown")
end

----------------------------
-- command decoders
----------------------------

----------------------------------------------
-- pvaClientSearchDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
    for i=0, n_protocols -1 do
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

        for i=0, n_pvs -1 do
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
-- pvaServerBeaconDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvaServerSearchResponseDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvaClientValidateDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvsServerValidateDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvaClientCreateChannelDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvaServerCreateChannelDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
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
-- pvaDestroyChannelDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaDestroyChannelDecoder (buf, pkt, tree, is_big_endian, cmd)
    local cid = getUint64(buf, is_big_endian)
    local sid = getUint64(buf(4), is_big_endian)
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fsid, buf(0,4), sid)
    tree:add(fcid, buf(4,4), cid)
end

----------------------------------------------
-- pvaClientDestroyDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
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
-- pvaGenericClientOpDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericClientOpDecoder (buf, pkt, tree, is_big_endian, cmd)
    local sub_command, request_id, bitset
    request_id, sub_command, buf = decodeSubCommand(buf, pkt, tree, is_big_endian, cmd, true)

    if not buf or buf:len() < 1 then return end

    -- if the subcommand is INIT then no change BitSet - just introspect
    if bit.band(sub_command, 0x08) ~= 0 then
        -- no status for clients, just the optional Introspection Data
        local pvd_tree = tree:add(buf, "PVData Introspection")
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == MONITOR_MESSAGE then
        -- Monitor messages have a changed bitset
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    end

    -- Process remaining payload
    if buf and buf:len() > 0 then
        local pvd_tree = tree:add(buf, "PVData")
        pvaDecodePVData(buf, pvd_tree, is_big_endian, request_id, bitset)
    end
end


----------------------------------------------
-- pvaGenericServerOpDecoder: decode the given message body into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericServerOpDecoder (buf, pkt, tree, is_big_endian, cmd)
    local sub_command, request_id, bitset
    request_id, sub_command, buf = decodeSubCommand(buf, pkt, tree, is_big_endian, cmd, false)

    if (cmd ~= MONITOR_UPDATE and bit.band(sub_command, 0x08) ~= 0) then
        buf = decodeStatus(buf, tree, is_big_endian)
    end

    if not buf or buf:len() < 1 then return end

    -- if the subcommand is INIT then no change BitSet - just introspect
    if bit.band(sub_command, 0x08) ~= 0 then
        -- optional Introspection Data
        local pvd_tree = tree:add(buf, "PVData Introspection")
        buf = pvaDecodePVDataType(buf, pvd_tree, is_big_endian, request_id)
    elseif cmd == MONITOR_MESSAGE then
        -- Monitor messages have a changed bitset
        bitset, buf = getBitSet(buf, is_big_endian)
        if not buf then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated PVData")
            return
        end
    end

    -- Process remaining payload
    if buf and buf:len() > 0 then
        local pvd_tree = tree:add(buf, "PVData")
        pvaDecodePVData(buf, pvd_tree, is_big_endian, request_id, bitset)
    end
end

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
    [ARRAY_MESSAGE] =                   pvaGenericServerOpDecoder,
    [RPC_MESSAGE] =                     pvaGenericServerOpDecoder,
}

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
-- decode: decode the given buffer into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param root: the root tree node to decode into
-- @return the number of bytes consumed
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

    local buf = buf(PVA_HEADER_LEN, message_len);
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
-- dissector: the dissector function
-- Implementation of the PVA disector
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param root: the root tree node to decode into
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

local status, err = pcall(function() pva:register_heuristic("udp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic UDP dissector.  Must manually specify UDP port! (try newer wireshark?)")
    print(err)
end

io.stderr:write("Loaded PVA\n")
