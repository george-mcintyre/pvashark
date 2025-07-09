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
-- Simple TypeCodes
----------------------------------------------

local TYPE_CODE_BOOLEAN                 = 0x00;

local TYPE_CODE_BYTE                    = 0x20;
local TYPE_CODE_SHORT                   = 0x21;
local TYPE_CODE_INT                     = 0x22;
local TYPE_CODE_LONG                    = 0x23;

local TYPE_CODE_UBYTE                   = 0x24;
local TYPE_CODE_USHORT                  = 0x25;
local TYPE_CODE_UINT                    = 0x26;
local TYPE_CODE_ULONG                   = 0x27;

local TYPE_CODE_FLOAT                   = 0x42;
local TYPE_CODE_DOUBLE                  = 0x43;

local TYPE_CODE_STRING                  = 0x60;

local TYPE_CODE_STRUCT                  = 0x80;
local TYPE_CODE_UNION                   = 0x81;
local TYPE_CODE_ANY                     = 0x82;

----------------------------------------------
-- Array TypeCodes
----------------------------------------------

local TYPE_CODE_BOOLEAN_ARRAY           = 0x08;

local TYPE_CODE_BYTE_ARRAY              = 0x28;
local TYPE_CODE_SHORT_ARRAY             = 0x29;
local TYPE_CODE_INT_ARRAY               = 0x2A;
local TYPE_CODE_LONG_ARRAY              = 0x2B;

local TYPE_CODE_UBYTE_ARRAY             = 0x2C;
local TYPE_CODE_USHORT_ARRAY            = 0x2D;
local TYPE_CODE_UINT_ARRAY              = 0x2E;
local TYPE_CODE_ULONG_ARRAY             = 0x2F;

local TYPE_CODE_FLOAT_ARRAY             = 0x4A;
local TYPE_CODE_DOUBLE_ARRAY            = 0x4B;

local TYPE_CODE_STRING_ARRAY            = 0x68;

local TYPE_CODE_STRUCT_ARRAY            = 0x88;
local TYPE_CODE_UNION_ARRAY             = 0x89;
local TYPE_CODE_ANY_ARRAY               = 0x8A;

----------------------------------------------
-- Introspection (PVData) encoding types
----------------------------------------------

local FIELD_DESC_TYPE_FULL = 0xFD;      -- FULL_WITH_ID: full introspection + assign ID (two bytes) + FieldDesc
local FIELD_DESC_TYPE_ID_ONLY = 0xFE;   -- ONLY_ID: reference existing ID (two bytes) + PVData values
local FIELD_DESC_NULL = 0xFF;           -- NULL_TYPE: null field

----------------------------------------------
-- TypeCode to name mapping table
----------------------------------------------

local PVD_TYPES = {
    --
    [TYPE_CODE_BOOLEAN]                 = "bool",
    [TYPE_CODE_BYTE]                    = "int8_t",
    [TYPE_CODE_SHORT]                   = "int16_t",
    [TYPE_CODE_INT]                     = "int32_t",
    [TYPE_CODE_LONG]                    = "int64_t",
    [TYPE_CODE_UBYTE]                   = "uint8_t",
    [TYPE_CODE_USHORT]                  = "uint16_t",
    [TYPE_CODE_UINT]                    = "uint32_t",
    [TYPE_CODE_ULONG]                   = "uint64_t",
    [TYPE_CODE_FLOAT]                   = "float",
    [TYPE_CODE_DOUBLE]                  = "double",
    [TYPE_CODE_STRING]                  = "string",
    [TYPE_CODE_STRUCT]                  = "struct",
    [TYPE_CODE_UNION]                   = "union",
    [TYPE_CODE_ANY]                     = "any",

    -- Array types
    [TYPE_CODE_BOOLEAN_ARRAY]           = "bool[]",
    [TYPE_CODE_BYTE_ARRAY]              = "int8_t[]",
    [TYPE_CODE_SHORT_ARRAY]             = "int16_t[]",
    [TYPE_CODE_INT_ARRAY]               = "int32_t[]",
    [TYPE_CODE_LONG_ARRAY]              = "int64_t[]",
    [TYPE_CODE_UBYTE_ARRAY]             = "uint8_t[]",
    [TYPE_CODE_USHORT_ARRAY]            = "uint16_t[]",
    [TYPE_CODE_UINT_ARRAY]              = "uint32_t[]",
    [TYPE_CODE_ULONG_ARRAY]             = "uint64_t[]",
    [TYPE_CODE_FLOAT_ARRAY]             = "float[]",
    [TYPE_CODE_DOUBLE_ARRAY]            = "double[]",
    [TYPE_CODE_STRING_ARRAY]            = "string[]",
    [TYPE_CODE_STRUCT_ARRAY]            = "struct[]",
    [TYPE_CODE_UNION_ARRAY]             = "union[]",
    [TYPE_CODE_ANY_ARRAY]               = "any[]",
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

local fpvd_struct   = ProtoField.bytes(     "pva.pvd_struct",   "PVStructure")
local fpvd_field    = ProtoField.bytes(     "pva.pvd_field",    "Field")
local fpvd_field_name = ProtoField.string(  "pva.pvd_field_name", "Field Name")
local fpvd_type     = ProtoField.uint8(     "pva.pvd_type",     "Type",             base.HEX)
local fpvd_value    = ProtoField.bytes(     "pva.pvd_value",    "Value")
local fpvd_introspection = ProtoField.bytes("pva.pvd_introspection", "Introspection Data")
local fpvd_debug    = ProtoField.bytes(     "pva.pvd_debug",    "Debug Info")

----------------------------------------------
-- Common Fields
----------------------------------------------

local fcid          = ProtoField.uint32(    "pva.cid",          "Client Channel ID")
local fsid          = ProtoField.uint32(    "pva.sid",          "Server Channel ID")
local fioid         = ProtoField.uint32(    "pva.ioid",         "Operation ID")
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
    fcid, fsid, fioid, fsubcmd, fsubcmd_proc, fsubcmd_init, fsubcmd_dstr, fsubcmd_get, fsubcmd_gtpt, fstatus,
    fbeacon_seq, fbeacon_change,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_host, fvalid_method, fvalid_authority, fvalid_account, fvalid_user, fvalid_isTLS,
    fvalid_azflg, fvalid_azcnt, fauthz_request, fauthz_response,
    fpvd_struct, fpvd_field, fpvd_field_name, fpvd_type, fpvd_value, fpvd_introspection, fpvd_debug,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_mask_repl, fsearch_mask_bcast,
    fsearch_proto, fsearch_count, fsearch_cid, fsearch_name,
    fsearch_found,
}

----------------------------------------------
-- The Operation ID PVField Cache
----------------------------------------------

local FieldRegistry = {}

-- Initialize the registry
FieldRegistry.data = {}
FieldRegistry.roots = {}

-- Add a field to the registry
function FieldRegistry:addField(op_id, field_id, name, type_code, parent_field_id, type)
    -- Ensure op_id exists
    if not self.data[op_id] then
        self.data[op_id] = {}
    end

    -- Determine the type string
    local type_string = type or PVD_TYPES[type_code] or "<unknown>"

    -- Create the field entry
    local field = {
        name = name,
        type_code = type_code,
        type = type_string,
        sub_fields = {},      -- For simple fields, store sub-fields directly
        sub_field_refs = {},  -- For complex fields, store references
        op_id = op_id,        -- Ensure these are set
        field_id = field_id
    }

    -- Store the field only if it has a field_id (complex types)
    if field_id then
        self.data[op_id][field_id] = field
    end

    -- If parent_field_id is provided, add this field as a sub-field of the parent
    if parent_field_id then
        local parent_field = self:getField(op_id, parent_field_id)
        if parent_field then
            if field_id then
                -- Complex field: store reference
                table.insert(parent_field.sub_field_refs, field_id)
            else
                -- Simple field: store directly
                table.insert(parent_field.sub_fields, field)
            end
        end
    else
        -- This is a root field (has no parent)
        self.roots[op_id] = field
    end

    return field  -- Return the field object for immediate use
end

-- Reset all fields for a specific op_id
function FieldRegistry:resetFields(op_id)
    if self.data[op_id] then
        self.data[op_id] = nil
        self.roots[op_id] = nil
        return true
    end
    return false
end

-- Check if a field exists
function FieldRegistry:hasField(op_id, field_id)
    if self.data == nil then
        self.data = {}
    end

    if self.data[op_id] == nil then
        self.data[op_id] = {}
    end

    return self.data[op_id][field_id] ~= nil
end

-- Get a field from the registry
function FieldRegistry:getField(op_id, field_id)
    if self:hasField(op_id, field_id) then
        return self.data[op_id][field_id]
    end
    return nil
end

-- Get sub-field references for a field
function FieldRegistry:getSubFieldRefs(op_id, field_id)
    local field = self:getField(op_id, field_id)
    if field then
        return field.sub_field_refs
    end
    return {}
end

-- Get actual sub-field objects (resolves references)
function FieldRegistry:getSubFields(op_id, field_id)
    local field = self:getField(op_id, field_id)
    if not field then
        return {}
    end

    local sub_fields = {}

    -- Add direct sub-fields (simple types)
    for i, sub_field in ipairs(field.sub_fields or {}) do
        table.insert(sub_fields, sub_field)
    end

    -- Add referenced sub-fields (complex types)
    for i, sub_field_id in ipairs(field.sub_field_refs or {}) do
        local sub_field = self:getField(op_id, sub_field_id)
        if sub_field then
            table.insert(sub_fields, sub_field)
        end
    end

    return sub_fields
end

-- Get all fields for an op_id
function FieldRegistry:getFields(op_id)
    return self.data[op_id] or {}
end


-- Get a field by depth-first index within an op_id
function FieldRegistry:getIndexedField(op_id, index)
    local root_field = self.roots[op_id]

    if not root_field then
        return nil, nil  -- No root field found
    end

    -- Perform depth-first traversal
    local current_index = {value = 0}  -- Use table to pass by reference

    local function depth_first_traverse(field, target_index, path_parts)
        local current_field = field
        if not current_field then
            return nil, nil
        end

        -- Add current field name to path
        local current_path_parts = {}
        for i = 1, #path_parts do
            current_path_parts[i] = path_parts[i]
        end
        current_path_parts[#current_path_parts + 1] = current_field.name

        -- Check if this is the index we're looking for
        if current_index.value == target_index then
            local path = table.concat(current_path_parts, ".")
            return path, current_field
        end

        current_index.value = current_index.value + 1

        -- Recursively traverse sub-fields (depth-first)
        local all_sub_fields = self:getSubFields(current_field.op_id, current_field.field_id)
        for _, sub_field in ipairs(all_sub_fields) do
            local path, result = depth_first_traverse(sub_field, target_index, current_path_parts)
            if result then
                return path, result
            end
        end

        return nil, nil
    end

    return depth_first_traverse(root_field, index, {})
end

----------------------------------------------
-- Utility functions
----------------------------------------------

-- Check if a type code represents an array type
function isArrayType(type_code)
    return type_code == TYPE_CODE_BOOLEAN_ARRAY or
           type_code == TYPE_CODE_BYTE_ARRAY or
           type_code == TYPE_CODE_SHORT_ARRAY or
           type_code == TYPE_CODE_INT_ARRAY or
           type_code == TYPE_CODE_LONG_ARRAY or
           type_code == TYPE_CODE_UBYTE_ARRAY or
           type_code == TYPE_CODE_USHORT_ARRAY or
           type_code == TYPE_CODE_UINT_ARRAY or
           type_code == TYPE_CODE_ULONG_ARRAY or
           type_code == TYPE_CODE_FLOAT_ARRAY or
           type_code == TYPE_CODE_DOUBLE_ARRAY or
           type_code == TYPE_CODE_STRING_ARRAY or
           type_code == TYPE_CODE_STRUCT_ARRAY or
           type_code == TYPE_CODE_UNION_ARRAY or
           type_code == TYPE_CODE_ANY_ARRAY
end

----------------------------------------------
--- tvbToBinary: get an binary string of digits from buffer
--- @param tvb_range to read the bytes from
----------------------------------------------
function tvbToBinary(tvb_range)
    if not tvb_range or tvb_range:len() == 0 then
        return ""
    end

    local result = {}
    local bytes = tvb_range:bytes()

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
--- countFieldIndices: count how many field indices a field and its subfields occupy
--- @param field the field to count indices for
--- @param visited_ids table to track visited field IDs to prevent infinite recursion
--- @return the number of indices this field occupies
----------------------------------------------
function countFieldIndices(field, visited_ids)
    if not field then
        return 0
    end
    
    visited_ids = visited_ids or {}
    local count = 1  -- The field itself takes 1 index
    
    -- If it's a struct/union, add all subfield indices
    if (field.type_code == TYPE_CODE_STRUCT or field.type_code == TYPE_CODE_UNION) and 
       field.op_id and field.field_id then
        
        -- Create a unique key for this field to detect circular references
        local field_key = tostring(field.op_id) .. ":" .. tostring(field.field_id)
        
        -- Prevent infinite recursion
        if visited_ids[field_key] then
            return count  -- Just count this field, don't recurse
        end
        
        visited_ids[field_key] = true
        local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
        for _, sub_field in ipairs(sub_fields) do
            count = count + countFieldIndices(sub_field, visited_ids)
        end
        visited_ids[field_key] = nil  -- Remove from visited after processing
    end
    
    return count
end

----------------------------------------------
--- isFieldInBitSet: check if a field should be displayed based on bitset
--- @param bitset_str the binary string representation of the bitset
--- @param field_index the field's index in the depth-first traversal
----------------------------------------------
function isFieldInBitSet(bitset_str, field_index)
    if not bitset_str or bitset_str == "" then
        -- No bitset means show all fields (full update)
        return true
    end

    -- BitSet uses little-endian bit ordering
    -- bit_index should be within the length of bitset_str
    if field_index >= string.len(bitset_str) then
        return false
    end

    -- PVA bitsets are little-endian: bit 0 is RIGHTMOST
    -- Read from right to left: bit_position counts from the right
    local bit_position_from_right = string.len(bitset_str) - field_index
    local bit_char = string.sub(bitset_str, bit_position_from_right, bit_position_from_right)



    return bit_char == "1"
end

----------------------------------------------
--- getUint: get an unsigned integer with the correct byte order
--- @param src to read the uint from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getUint(src, is_big_endian)
    if src:len() == 1 then
        return src:byte()
    end
    if is_big_endian == nil or is_big_endian then
        if src:len() == 2 then
            return src:uint()
        else
            return src:uint64():tonumber()
        end
    else
        if src:len() == 2 then
            return src:le_uint()
        else
            return src:le_uint64():tonumber()
        end
    end
end

----------------------------------------------
--- getInt: get an integer with the correct byte order
--- @param src to read the int from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getInt(src, is_big_endian)
    if src:len() == 1 then
        return src:byte()
    end
    if is_big_endian == nil or is_big_endian then
        if src:len() == 2 then
            return src:int()
        else
            return src:int64():tonumber()
        end
    else
        if src:len() == 2 then
            return src:le_int()
        else
            return src:le_int64():tonumber()
        end
    end
end

----------------------------------------------
--- getUintForDisplay: get an unsigned integer formatted for display (avoiding .0 suffix)
--- @param src to read the uint from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getUintForDisplay(src, is_big_endian)
    if src:len() == 1 then
        return tostring(src:byte())
    end
    if is_big_endian == nil or is_big_endian then
        if src:len() == 2 then
            return tostring(src:uint())
        else
            return tostring(src:uint64())
        end
    else
        if src:len() == 2 then
            return tostring(src:le_uint())
        else
            return tostring(src:le_uint64())
        end
    end
end

----------------------------------------------
--- getIntForDisplay: get an integer formatted for display (avoiding .0 suffix)
--- @param src to read the int from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getIntForDisplay(src, is_big_endian)
    if src:len() == 1 then
        return tostring(src:byte())
    end
    if is_big_endian == nil or is_big_endian then
        if src:len() == 2 then
            return tostring(src:int())
        else
            return tostring(src:int64())
        end
    else
        if src:len() == 2 then
            return tostring(src:le_int())
        else
            return tostring(src:le_int64())
        end
    end
end

----------------------------------------------
--- getFloat: get a float with the correct byte order
--- @param src to read the float from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getFloat(src, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return src:float()
    else
        return src:le_float()
    end
end

----------------------------------------------
--- getDouble: get a double with the correct byte order
--- @param src to read the double from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getDouble(src, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return src:float()  -- Wireshark's float() method handles both 32-bit and 64-bit
    else
        return src:le_float()  -- Wireshark's le_float() method handles both 32-bit and 64-bit
    end
end

----------------------------------------------
--- getUint32: get an unsigned 32-bit integer with the correct byte order
--- @param src to read the int64 from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getUint32(src, is_big_endian)
    return getUint(src(0,2), is_big_endian)
end

----------------------------------------------
--- getUint64: get an unsigned 64-bit integer with the correct byte order
--- @param src to read the int64 from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getUint64(src, is_big_endian)
    return getUint(src(0,4), is_big_endian)
end


----------------------------------------------
-- decodeSize: decode a size from a TvbRange buffer using 3-tier encoding
--
-- Tier 1: 1 byte (0x00-0xFE) → value 0-254
-- Tier 2: 5 bytes (0xFF + 4-byte signed int32) → value 255-2^31-2
-- Tier 3: 13 bytes (0xFF + 0x7FFFFFFF + 8-byte signed int64) → value 2^31-1 to 2^63-1
--
-- @param buf           : TvbRange whose first byte is the Size
-- @param is_big_endian : boolean – true if the current TCP stream is BE
-- @returns             : size (number or Int64), remaining TvbRange
----------------------------------------------------------------
local function decodeSize(buf, is_big_endian)

    -- 1. fast path: single‑byte size 0‑254
    local first = buf:range(0,1):uint()      -- one byte
    if first < 0xFF then
        if buf:len() > 1 then
            return first, buf:range(1)       -- drop 1 byte
        else
            return first, nil                -- nothing remains after droping a byte
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
-- @param message_body: the buffer to decode from
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function decodeStatus (message_body, tree, is_big_endian)
    local status_code = message_body(0,1):uint()
    local sub_tree = tree:add(fstatus, message_body(0,1))
    if message_body:len()>1 then
        message_body = message_body(1)
    end

    if status_code ==0xFF then
        return message_body
    else
        local message, stack
        message, message_body = decodeString(message_body, is_big_endian)
        stack, message_body = decodeString(message_body, is_big_endian)
        sub_tree:append_text(message:string())
        if(status_code ~=0 and stack:len()>0)
        then
            sub_tree:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
        end
        return message_body
    end
end

function transposeNtNames(field_name)

end


function decodeStruct(remaining_buf, is_big_endian, op_id, field_id, parent_field_id, type_code, name)
    -- Check if we have enough data for the type string
    if not remaining_buf or remaining_buf:len() == 0 then
        return nil, remaining_buf
    end

    local type_id
    type_id, remaining_buf = decodeString(remaining_buf, is_big_endian)

    -- Check if decodeString succeeded
    if not remaining_buf then
        return nil, nil
    end

    local display_name
    if type_id and type_id ~= "" and nt_types[type_id] then
        -- Normative type: use short name
        display_name = nt_types[type_id]
    elseif name and name ~= "" then
        -- Use the field name from the enclosing structure
        display_name = name
    elseif type_id and type_id ~= "" then
        -- Fallback: use the type string
        display_name = type_id
    else
        -- Final fallback: "value"
        display_name = "value"
    end

    local field = FieldRegistry:addField(op_id, field_id, display_name, type_code, parent_field_id)

    local count
    count, remaining_buf = decodeSize(remaining_buf, is_big_endian)

    -- Check if decodeSize succeeded
    if not remaining_buf then
        return field, nil
    end

    for i = 1, count do
        local field_name
        field_name, remaining_buf = decodeString(remaining_buf, is_big_endian)

        -- Check if remaining_buf is valid before proceeding
        if not remaining_buf or remaining_buf:len() == 0 then
            break
        end

        -- Sub-fields in a struct are regular field definitions
        local sub_field
        sub_field, remaining_buf = decodeField(remaining_buf, is_big_endian, op_id, nil, field_id, field_name)

        -- Check if remaining_buf is still valid after decodeField
        if not remaining_buf then
            break
        end
    end

    return field, remaining_buf
end

function decodeUnion(remaining_buf, is_big_endian, op_id, field_id, parent_field_id, type_code, name)
    local type_id
    type_id, remaining_buf = decodeString(remaining_buf, is_big_endian)

    local display_name
    if type_id and type_id ~= "" and nt_types[type_id] then
        -- Normative type: use short name
        display_name = nt_types[type_id]
    elseif name and name ~= "" then
        -- Use the field name from the enclosing structure
        display_name = name
    elseif type_id and type_id ~= "" then
        -- Fallback: use the type string
        display_name = type_id
    else
        -- Final fallback: "value"
        display_name = "value"
    end

    local field = FieldRegistry:addField(op_id, field_id, display_name, type_code, parent_field_id)

    local count
    count, remaining_buf = decodeSize(remaining_buf, is_big_endian)

    for i = 1, count do
        local field_name
        field_name, remaining_buf = decodeString(remaining_buf, is_big_endian)

        -- Check if remaining_buf is valid before proceeding
        if not remaining_buf or remaining_buf:len() == 0 then
            break
        end

        -- Sub-fields in a union are regular field definitions
        local sub_field
        sub_field, remaining_buf = decodeField(remaining_buf, is_big_endian, op_id, nil, field_id, field_name)

        -- Check if remaining_buf is still valid after decodeField
        if not remaining_buf then
            break
        end
    end

    return field, remaining_buf
end

-- Parse PVData for a field (recurses children) to extract and store a field definition
function decodeField(pvdata_buf, is_big_endian, op_id, field_id, parent_field_id, given_name)
    if not pvdata_buf or pvdata_buf:len() < 2 then
        return nil, pvdata_buf
    end

    -- reset fields if this is the top level
    if not parent_field_id then FieldRegistry:resetFields(op_id) end

    -- Read Type code
    local type_code = pvdata_buf(0, 1):uint()

    local remaining_buf = pvdata_buf:range(1)

    -- Handle introspection type codes
    if type_code == FIELD_DESC_TYPE_FULL then
        -- 0xFD: FULL_WITH_ID_TYPE_CODE - extract the field ID and decode the field
        if remaining_buf:len() < 2 then
            return nil, remaining_buf
        end

        local cached_field_id = getUint(remaining_buf(0, 2), is_big_endian)
        remaining_buf = remaining_buf:range(2)

        -- Now decode the actual field definition, using the extracted field ID
        return decodeField(remaining_buf, is_big_endian, op_id, cached_field_id, parent_field_id, given_name)

    elseif type_code == FIELD_DESC_TYPE_ID_ONLY then
        -- 0xFE: ONLY_ID_TYPE_CODE - just reference an existing field ID
        if remaining_buf:len() < 2 then
            return nil, remaining_buf
        end

        local cached_field_id = getUint(remaining_buf(0, 2), is_big_endian)
        remaining_buf = remaining_buf:range(2)

        -- Look up the cached field and create a reference
        local cached_field = FieldRegistry:getField(op_id, cached_field_id)
        if cached_field and parent_field_id then
            local parent_field = FieldRegistry:getField(op_id, parent_field_id)
            if parent_field then
                table.insert(parent_field.sub_field_refs, cached_field_id)
            end
        end

        return cached_field, remaining_buf
    end

    -- Handle regular field type codes
    if type_code == TYPE_CODE_STRUCT or type_code == TYPE_CODE_STRUCT_ARRAY or type_code == TYPE_CODE_ANY or type_code == TYPE_CODE_ANY_ARRAY then
        return decodeStruct(remaining_buf, is_big_endian, op_id, field_id, parent_field_id, type_code, given_name)
    elseif type_code == TYPE_CODE_UNION or type_code == TYPE_CODE_UNION_ARRAY then
        return decodeUnion(remaining_buf, is_big_endian, op_id, field_id, parent_field_id, type_code, given_name)
    elseif type_code == TYPE_CODE_BOOLEAN
            or type_code == TYPE_CODE_BYTE
            or type_code == TYPE_CODE_SHORT
            or type_code == TYPE_CODE_INT
            or type_code == TYPE_CODE_LONG
            or type_code == TYPE_CODE_UBYTE
            or type_code == TYPE_CODE_USHORT
            or type_code == TYPE_CODE_UINT
            or type_code == TYPE_CODE_ULONG
            or type_code == TYPE_CODE_FLOAT
            or type_code == TYPE_CODE_DOUBLE
            or type_code == TYPE_CODE_STRING
            or type_code == TYPE_CODE_BOOLEAN_ARRAY
            or type_code == TYPE_CODE_BYTE_ARRAY
            or type_code == TYPE_CODE_SHORT_ARRAY
            or type_code == TYPE_CODE_INT_ARRAY
            or type_code == TYPE_CODE_LONG_ARRAY
            or type_code == TYPE_CODE_UBYTE_ARRAY
            or type_code == TYPE_CODE_USHORT_ARRAY
            or type_code == TYPE_CODE_UINT_ARRAY
            or type_code == TYPE_CODE_ULONG_ARRAY
            or type_code == TYPE_CODE_FLOAT_ARRAY
            or type_code == TYPE_CODE_DOUBLE_ARRAY
            or type_code == TYPE_CODE_STRING_ARRAY
    then
        local field = FieldRegistry:addField(op_id, field_id, given_name, type_code, parent_field_id)
        return field, remaining_buf
    end

end

-- Display a single field and move the buf pointer along - skip any non-scalar type_code
function displayField(pvdata_buf, tree, is_big_endian, pvdata_type, field, bitset_str, field_index)
    if field == nil then
        return nil, field_index or 0
    end
    local remaining_buf = pvdata_buf
    local current_index = field_index or 0
    




    if field.type_code == TYPE_CODE_STRUCT or
       field.type_code == TYPE_CODE_UNION or
       field.type_code == TYPE_CODE_STRUCT_ARRAY or
       field.type_code == TYPE_CODE_UNION_ARRAY then
        
        if not field.op_id or not field.field_id then
            return remaining_buf, current_index + 1
        end
        
        local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
        local sub_index = current_index + 1
        
        -- Check if this struct field should be displayed
        if isFieldInBitSet(bitset_str, current_index) then
            -- Struct bit is set - ALL subfields are present in data stream
            local sub_tree = nil
            if tree then
                sub_tree = tree:add(remaining_buf, string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
            end

            -- Pass nil for bitset to force reading all subfields since parent struct bit is set
            for i, sub_field in ipairs(sub_fields) do
                remaining_buf, sub_index = displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, nil, sub_index)
            end
            return remaining_buf, sub_index
        else
            -- Struct bit is NOT set - check individual subfield bits
            -- Some subfields may be present, others may not
            local sub_tree = nil
            local any_subfield_present = false
            
            -- First pass: check if any subfields are present
            for i, sub_field in ipairs(sub_fields) do
                if isFieldInBitSet(bitset_str, sub_index) then
                    any_subfield_present = true
                    break
                end
                sub_index = sub_index + 1
            end
            
            -- Reset sub_index for actual processing
            sub_index = current_index + 1
            
            if any_subfield_present and tree then
                sub_tree = tree:add(remaining_buf, string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
            end
            
            -- Process each subfield individually based on its bit
            for i, sub_field in ipairs(sub_fields) do
                remaining_buf, sub_index = displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, bitset_str, sub_index)
            end
            return remaining_buf, sub_index
        end
    end

    -- simple types
    local data_len
    if pvdata_type == 0x00 then
        -- there is actual data to parse out and point to
        data_len = getTypeSize(field.type_code)

        -- Add bounds checking for fixed-size types
        if data_len > 0 and remaining_buf:len() < data_len then
            if tree then  -- Only show error if we're displaying
                tree:add_expert_info(PI_MALFORMED, PI_ERROR,
                    string.format("Insufficient buffer for %s: need %d bytes, have %d",
                    field.name or "field", data_len, remaining_buf:len()))
            end
            return remaining_buf, current_index + 1
        end

        -- Check if this field should be displayed based on bitset
        -- If bitset_str is nil, it means parent struct bit was set, so display all subfields
        local should_display
        if bitset_str == nil then
            -- Parent struct was selected, so display all subfields without bitset checking
            should_display = tree ~= nil
        else
            -- Check individual field bit in bitset
            should_display = isFieldInBitSet(bitset_str, current_index) and tree ~= nil
        end
        if field.type_code == TYPE_CODE_BOOLEAN then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %s", field.name, field.type_code, field.type, tostring(remaining_buf(0, 1):uint() == 0)))
            end
            if remaining_buf:len() >= data_len then
                remaining_buf = remaining_buf:range(data_len)
            else
                remaining_buf = remaining_buf:range(remaining_buf:len())
            end
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_BYTE then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %d", field.name, field.type_code, field.type, remaining_buf(0, 1):int()))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_UBYTE then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %d", field.name, field.type_code, field.type, remaining_buf(0, 1):uint()))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_SHORT or field.type_code == TYPE_CODE_INT or field.type_code == TYPE_CODE_LONG then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %s", field.name, field.type_code, field.type, getIntForDisplay(remaining_buf(0, data_len), is_big_endian)))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_USHORT or field.type_code == TYPE_CODE_UINT or field.type_code == TYPE_CODE_ULONG then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %s", field.name, field.type_code, field.type, getUintForDisplay(remaining_buf(0, data_len), is_big_endian)))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_FLOAT then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %g", field.name, field.type_code, field.type, getFloat(remaining_buf(0, data_len), is_big_endian)))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_DOUBLE then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %g", field.name, field.type_code, field.type, getDouble(remaining_buf(0, data_len), is_big_endian)))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_STRING then
            local str_value, after_string_buf = decodeString(remaining_buf, is_big_endian)
            if str_value then
                local consumed = remaining_buf:len() - (after_string_buf and after_string_buf:len() or 0)
                if should_display then
                    tree:add(remaining_buf(0, consumed), string.format("%s (0x%02X: %s): %s", field.name, field.type_code, field.type, str_value))
                end
                remaining_buf = after_string_buf or remaining_buf
            else
                if should_display then
                    tree:add(remaining_buf(0, 1), string.format("%s (0x%02X: %s): [invalid string]", field.name, field.type_code, field.type))
                end
                remaining_buf = remaining_buf:range(1)
            end
            return remaining_buf, current_index + 1
        elseif field.type_code == TYPE_CODE_STRUCT then
            -- When we reach a struct field, we need to read ALL its subfields from data
            -- because they are present regardless of individual bits
            local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
            local sub_index = current_index + 1

            if should_display then
                local sub_tree = tree:add(remaining_buf(0, 1), string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
                for _, sub_field in ipairs(sub_fields) do
                    -- Pass nil for bitset since we're inside a struct that was selected
                    remaining_buf, sub_index = displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                end
            else
                -- Field not displayed but still need to consume data for all subfields
                for _, sub_field in ipairs(sub_fields) do
                    remaining_buf, sub_index = displayField(remaining_buf, nil, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                end
            end
            return remaining_buf, sub_index
        elseif field.type_code == TYPE_CODE_UNION then
            -- When we reach a union field, we need to read ALL its data
            local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
            local sub_index = current_index + 1

            if should_display then
                local sub_tree = tree:add(remaining_buf(0, 1), string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
                for _, sub_field in ipairs(sub_fields) do
                    -- Pass nil for bitset since we're inside a union that was selected
                    remaining_buf, sub_index = displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                end
            else
                -- Field not displayed but still need to consume data for all subfields
                for _, sub_field in ipairs(sub_fields) do
                    remaining_buf, sub_index = displayField(remaining_buf, nil, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                end
            end
            return remaining_buf, sub_index
        elseif field.type_code == TYPE_CODE_STRUCT_ARRAY then
            local count = getUint32(remaining_buf, is_big_endian)
            remaining_buf = remaining_buf:range(4)
            local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
            local sub_index = current_index + 1

            if should_display then
                local array_tree = tree:add(remaining_buf(0, 1), string.format("%s[] (0x%02X: %s[])", field.name, field.type_code, field.type))
                for i = 1, count do
                    local sub_tree = array_tree:add(remaining_buf(0, 1), string.format("%s[%d] (0x%02X: %s)", field.name, i - 1, field.type_code, field.type))
                    for _, sub_field in ipairs(sub_fields) do
                        -- Pass nil for bitset since we're inside a struct array that was selected
                        remaining_buf, sub_index = displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                    end
                end
            else
                -- Still need to consume data for all subfields even if not displaying
                for i = 1, count do
                    for _, sub_field in ipairs(sub_fields) do
                        remaining_buf, sub_index = displayField(remaining_buf, nil, is_big_endian, pvdata_type, sub_field, nil, sub_index)
                    end
                end
            end
            return remaining_buf, sub_index
        elseif field.type_code == TYPE_CODE_UNION_ARRAY then
            if should_display then
                tree:add(remaining_buf(0, data_len), string.format("%s (0x%02X: %s): %s", field.name, field.type_code, field.type, remaining_buf(0, 1):string()))
            end
            remaining_buf = remaining_buf:range(data_len)
            return remaining_buf, current_index + 1
        elseif isArrayType(field.type_code) then
            -- Check if we have enough bytes for the array count
            if remaining_buf:len() < 4 then
                if tree then  -- Only show error if we're displaying
                    tree:add_expert_info(PI_MALFORMED, PI_ERROR,
                        string.format("Insufficient buffer for array count: need 4 bytes, have %d", remaining_buf:len()))
                end
                return remaining_buf, current_index + 1
            end
            local count = getUint32(remaining_buf, is_big_endian)
            remaining_buf = remaining_buf:range(4)
            local array_tree = nil
            if should_display then
                array_tree = tree:add(remaining_buf(0, data_len * count), string.format("%s[] (0x%02X: %s[])", field.name, field.type_code, field.type))
            end
            for i = 1, count do
                if field.type_code == TYPE_CODE_BOOLEAN_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %s", field.name, i - 1, field.type_code, field.type, tostring(remaining_buf(0, 1):uint() == 0)))
                    end
                elseif field.type_code == TYPE_CODE_BYTE_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %d", field.name, i - 1, field.type_code, field.type, remaining_buf(0, 1):int()))
                    end
                elseif field.type_code == TYPE_CODE_UBYTE_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %d", field.name, i - 1, field.type_code, field.type, remaining_buf(0, 1):uint()))
                    end
                elseif field.type_code == TYPE_CODE_SHORT_ARRAY or field.type_code == TYPE_CODE_INT_ARRAY or field.type_code == TYPE_CODE_LONG_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %s", field.name, i - 1, field.type_code, field.type, getIntForDisplay(remaining_buf(0, data_len), is_big_endian)))
                    end
                elseif field.type_code == TYPE_CODE_USHORT_ARRAY or field.type_code == TYPE_CODE_UINT_ARRAY or field.type_code == TYPE_CODE_ULONG_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %s", field.name, i - 1, field.type_code, field.type, getUintForDisplay(remaining_buf(0, data_len), is_big_endian)))
                    end
                elseif field.type_code == TYPE_CODE_FLOAT_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %g", field.name, i - 1, field.type_code, field.type, getFloat(remaining_buf(0, data_len), is_big_endian)))
                    end
                elseif field.type_code == TYPE_CODE_DOUBLE_ARRAY then
                    if array_tree then
                        array_tree:add(remaining_buf(0, data_len), string.format("%s[%d] (0x%02X: %s): %g", field.name, i - 1, field.type_code, field.type, getDouble(remaining_buf(0, data_len), is_big_endian)))
                    end
                elseif field.type_code == TYPE_CODE_STRING_ARRAY then
                    local str_value, after_string_buf = decodeString(remaining_buf, is_big_endian)
                    if str_value then
                        local consumed = remaining_buf:len() - (after_string_buf and after_string_buf:len() or 0)
                        if array_tree then
                            array_tree:add(remaining_buf(0, consumed), string.format("%s[%d] (0x%02X: %s): %s", field.name, i - 1, field.type_code, field.type, str_value))
                        end
                        remaining_buf = after_string_buf or remaining_buf
                    else
                        if array_tree then
                            array_tree:add(remaining_buf(0, 1), string.format("%s[%d] (0x%02X: %s): [invalid string]", field.name, i - 1, field.type_code, field.type))
                        end
                        remaining_buf = remaining_buf:range(1)
                    end
                else
                    -- For all other fixed-size array types
                    remaining_buf = remaining_buf:range(data_len)
                end
            end
            return remaining_buf, current_index + 1
        else
            -- just point to whole buffer
            data_len = pvdata_buf:len()

            if should_display then
                if isArrayType(field.type_code) then
                    tree:add(pvdata_buf(0, data_len), string.format("%s[] (0x%02X: %s[])", field.name, field.type_code, field.type))
                else
                    tree:add(pvdata_buf(0, data_len), string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
                end
            end

            -- don't move buffer pointer
        end
        return remaining_buf, current_index + 1
    else
        -- For field definitions (not data), show the field structure and recurse for structs/unions
        if field.type_code == TYPE_CODE_STRUCT or field.type_code == TYPE_CODE_UNION then
            -- Add a subtree for the struct/union in introspection mode
            if tree then
                local sub_tree = tree:add(remaining_buf(0, 1), string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
                if field.op_id and field.field_id then
                    local sub_fields = FieldRegistry:getSubFields(field.op_id, field.field_id)
                    for i, sub_field in ipairs(sub_fields) do
                        displayField(remaining_buf, sub_tree, is_big_endian, pvdata_type, sub_field, nil, 0)
                    end
                end
            end
        elseif isArrayType(field.type_code) then
            if tree then
                tree:add(remaining_buf(0, 1), string.format("%s[] (0x%02X: %s[])", field.name, field.type_code, field.type))
            end
        else
            if tree then
                tree:add(remaining_buf(0, 1), string.format("%s (0x%02X: %s)", field.name, field.type_code, field.type))
            end
        end
        return remaining_buf, current_index + 1
    end
end

-- Parse PVData, updating tree with structure and optional data, returning remaining buffer
function decodePVField(pvdata_buf, tree, is_big_endian, op_id, bitset_str, dont_display, name, parent_field_id)
    if not pvdata_buf or pvdata_buf:len() == 0 then
        return pvdata_buf
    end

    if bitset_str then
        -- Data only - use cached field definition to build tree with data

        -- Look up the root field from the cache
        local root_field = nil
        if FieldRegistry.roots and FieldRegistry.roots[op_id] then
            root_field = FieldRegistry.roots[op_id]
        end

        if root_field then
            -- Use the cached field definition to build proper hierarchical tree with data values
                         -- Call displayField with pvdata_type = 0x00 to enable data parsing mode
             if dont_display == nil or dont_display ~= true then
                 remaining_buf, _ = displayField(pvdata_buf, tree, is_big_endian, 0x00, root_field, bitset_str, 0)
             end
        else
            -- No cached field definition available
            if dont_display == nil or dont_display ~= true then
                tree:add_expert_info(PI_PROTOCOL, PI_WARN, "No cached field definition found for operation " .. tostring(op_id))
            end
        end

        return remaining_buf
    end

    -- Check first byte to determine introspection type
    local pvdata_type = pvdata_buf(0, 1):uint()

    if not pvdata_buf or pvdata_buf:len() < 2 then

        local field
        field, remaining_buf = decodeField(pvdata_buf, is_big_endian, op_id, 0, parent_field_id, name)

        -- display the parsed field
        if dont_display == nil or dont_display ~= true then
            displayField(pvdata_buf, tree, is_big_endian, pvdata_type, field, nil, 0)
        end

        return remaining_buf
        --return nil
    end
    local remaining_buf = pvdata_buf:range(1)
    pvdata_buf = remaining_buf


    if pvdata_type == FIELD_DESC_TYPE_FULL then
        -- 0xFD: introspection + 16-bit type ID + FieldDesc

        if remaining_buf:len() < 2 then
            if dont_display == nil or dont_display ~= true then
                tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated field descriptor")
            end
            return remaining_buf
        end

        local field_id = getUint32(remaining_buf, is_big_endian)
        remaining_buf = remaining_buf:range(2)

        -- Parse the FieldDesc that follows
        local field, remaining_buf = decodeField(remaining_buf, is_big_endian, op_id, field_id, parent_field_id, name)

        -- display the parsed field
        if dont_display == nil or dont_display ~= true then
            displayField(pvdata_buf, tree, is_big_endian, pvdata_type, field, nil, 0)
        end

        return remaining_buf

    elseif pvdata_type == FIELD_DESC_TYPE_ID_ONLY then
        -- 0xFE: ONLY_ID - reference to cached type + PVData values


        local new_remaining_buf
        local changed_bit_set
        changed_bit_set, new_remaining_buf = decodeSize(remaining_buf, is_big_endian)
        if dont_display == nil or dont_display ~= true then
            tree:add(remaining_buf(0, remaining_buf:len() - new_remaining_buf:len()), string.format("Change BitSet: %d", changed_bit_set))
        end
        remaining_buf = new_remaining_buf

        if remaining_buf:len() < 2 then
            if dont_display == nil or dont_display ~= true then
                tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated field descriptor")
            end
            return remaining_buf
        end

        local field_id = getUint32(remaining_buf, is_big_endian)
        remaining_buf = remaining_buf:range(2)

        -- Lookup cached field definition
        local field = FieldRegistry:getField(op_id, field_id)

        -- display the field and get data from buffer
        if dont_display == nil or dont_display ~= true then
            remaining_buf, _ = displayField(pvdata_buf, tree, is_big_endian, pvdata_type, field, nil, 0)
        end

        return remaining_buf

    elseif pvdata_type == FIELD_DESC_NULL then
        -- 0xFF: NULL_TYPE - null field

        return remaining_buf

    else
        -- Handle simple types (not 0xFD, 0xFE, 0xFF)
        -- Simple types don't have field IDs - use nil
        -- Need to reconstruct the buffer with the type code byte included
        local type_code_buf = pvdata_buf:range(0, 1)
        local combined_buf = pvdata_buf:range(0, remaining_buf:len() + 1)



        local field
        field, remaining_buf = decodeField(combined_buf, is_big_endian, op_id, nil, parent_field_id, name)

        -- display the parsed field
        if dont_display == nil or dont_display ~= true then
            displayField(combined_buf, tree, is_big_endian, pvdata_type, field, nil, 0)
        end

        return remaining_buf
    end


    return nil -- Consumed all data
end

-- Parse PVData returning remaining buffer
function pvaDecodePVData(pvdata_buf, tree, is_big_endian, op_id, bitset)
    local bitset_str
    if bitset then
        bitset_str = tvbToBinary(bitset)
        tree:add(bitset, string.format("Changed BitSet (%d bytes): %s", bitset:len(), bitset_str))
    end
    local remaining_buf = decodePVField(pvdata_buf, tree, is_big_endian, op_id, bitset_str, nil, nil, nil)
    if remaining_buf and remaining_buf:len() > 0 then tree:add(remaining_buf, "Unrecognised Op Data") end
end

-- Format field type for display
function formatFieldType(field)
    if not field or not field.type_code then
        return "unknown"
    end

    return string.format("0x%02x: %s", field.type_code, field.type or "unknown")
end

-- Parse MONITOR INIT introspection data (no ChangedBitSet)
function pvaDecodeMonitorInit(pvdata_buf, tree, is_big_endian, op_id)
    if pvdata_buf:len() < 1 then
        return pvdata_buf
    end

    local pvdata_type = pvdata_buf:range(0, 1):uint()

    if pvdata_type == FIELD_DESC_TYPE_ID_ONLY then
        -- 0xFE: ONLY_ID - reference to cached type (no ChangedBitSet for MONITOR INIT)
        if pvdata_buf:len() < 3 then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Truncated field descriptor")
            return pvdata_buf
        end

        -- Field ID is 2 bytes in PVA protocol
        local field_id = getUint(pvdata_buf:range(1, 2), is_big_endian)

        -- Add the cached field ID to display
        tree:add(pvdata_buf(0,3), string.format("Cached Field ID: (0x%04x)", field_id))

        -- Lookup cached field definition
        local field = FieldRegistry:getField(op_id, field_id)

        -- Display the field
        if field then
            displayField(pvdata_buf, tree, is_big_endian, pvdata_type, field, nil, 0)
        end

        -- Return empty buffer if we consumed all 3 bytes
        if pvdata_buf:len() <= 3 then
            return nil
        else
            return pvdata_buf:range(3)
        end
    else
        -- For other introspection types, use the normal decoder
        return decodePVField(pvdata_buf, tree, is_big_endian, op_id, nil, nil, nil, nil)
    end
end

----------------------------
-- command decoders
----------------------------

----------------------------------------------
-- pvaClientSearchDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientSearchDecoder (message_body, pkt, tree, is_big_endian)
    local SEARCH_HEADER_SIZE = 26
    local raw_sequence_number = message_body(0,4)
    local sequence_number = getUint(raw_sequence_number, is_big_endian)
    local port = getUint(message_body(24,2), is_big_endian)
    pkt.cols.info:append("SEARCH(".. sequence_number)

    tree:add(fsearch_seq, raw_sequence_number, sequence_number)

    local raw_mask = message_body(4,1)
    local mask = tree:add(fsearch_mask, raw_mask)
    mask:add(fsearch_mask_repl, raw_mask)
    mask:add(fsearch_mask_bcast, raw_mask)
    tree:add(fsearch_addr, message_body(8,16))
    tree:add(fsearch_port, message_body(24,2), port)

    local n_protocols

    -- get protocols list
    n_protocols, message_body = decodeSize(message_body(SEARCH_HEADER_SIZE), is_big_endian)
    for i=0, n_protocols -1 do
        local name
        name, message_body = decodeString(message_body, is_big_endian)
        tree:add(fsearch_proto, name)
    end

    -- get pvs list
    local raw_n_pv = message_body(0,2)
    local n_pvs = getUint(raw_n_pv, is_big_endian)
    tree:add(fsearch_count, raw_n_pv, n_pvs);
    if n_pvs >0 then
        message_body = message_body(2)

        for i=0, n_pvs -1 do
            local name
            local raw_cid = message_body(0,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            name, message_body = decodeString(message_body(4), is_big_endian)
            tree:add(fsearch_name, name)

            pkt.cols.info:append(', '..cid..":'"..name.."'")
        end
    end
    pkt.cols.info:append("), ")
end

----------------------------------------------
-- pvaServerBeaconDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerBeaconDecoder (message_body, pkt, tree, is_big_endian)
    local raw_beacon_header = message_body(0,12)
    tree:add(fguid, raw_beacon_header)
    local sequence_number = getUint(message_body(13,1), is_big_endian)
    local change = getUint(message_body(14,2), is_big_endian)
    local port = getUint(message_body(32,2), is_big_endian)
    tree:add(fbeacon_seq, message_body(13,1), sequence_number)
    tree:add(fbeacon_change, message_body(14,2), change)
    tree:add(fsearch_addr, message_body(16,16))
    tree:add(fsearch_port, message_body(32,2), port)

    pkt.cols.info:append("BEACON(0x".. raw_beacon_header ..", ".. sequence_number ..", "..change..")")

    local proto
    proto, message_body = decodeString(message_body(34), is_big_endian)
    tree:add(fsearch_proto, proto)
end

----------------------------------------------
-- pvaServerSearchResponseDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerSearchResponseDecoder (message_body, pkt, tree, is_big_endian)
    local sequence_number = getUint(message_body(12,4), is_big_endian)
    local port = getUint(message_body(32,2), is_big_endian)
    pkt.cols.info:append("SEARCH_RESPONSE(".. sequence_number)

    tree:add(fguid, message_body(0,12))
    tree:add(fsearch_seq, message_body(12,4), sequence_number)
    tree:add(fsearch_addr, message_body(16,16))
    tree:add(fsearch_port, message_body(32,2), port)

    local proto
    proto, message_body = decodeString(message_body(34), is_big_endian)
    tree:add(fsearch_proto, proto)

    tree:add(fsearch_found, message_body(0, 1))

    local n_pvs = getUint(message_body(1,2), is_big_endian)
    if n_pvs >0 then
        message_body = message_body(3)
        for i=0, n_pvs -1 do
            local raw_cid = message_body(i*4,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            pkt.cols.info:append(', '..cid)
        end
    end
    pkt.cols.info:append(")")

end

----------------------------------------------
-- pvaClientValidateDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientValidateDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local bsize  = getUint(message_body(0,4), is_big_endian)
    local isize = getUint(message_body(4,2), is_big_endian)
    local qos = getUint(message_body(6,2), is_big_endian)
    tree:add(fvalid_bsize, message_body(0,4), bsize)
    tree:add(fvalid_isize, message_body(4,2), isize)
    tree:add(fvalid_qos, message_body(6,2), qos)

    local method_range = message_body(8)
    local method
    method, message_body = decodeString(method_range, is_big_endian)

    -- Declare variables for authz processing
    local n_authz = 0
    local has_authz_extensions = false

    -- extensions to the AUTHZ message
    if (message_body and message_body:len() > 1)
    then
        local authzmessage, authzflags
        authzmessage = message_body(0,1):uint()
        if authzmessage == 0xfd
        then
            message_body = message_body(3)
        end
        -- Add authz flags at the main level (applies to all entries)
        tree:add(fvalid_azflg,  message_body(1,1))
        authzflags = message_body(1,1):uint()
        n_authz = message_body(2,1):uint()
        message_body = message_body(3)
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
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)

            local account_range = message_body
            account, message_body = decodeString(account_range, is_big_endian)
            local peer_range = message_body
            peer, message_body = decodeString(peer_range, is_big_endian)

            -- Add additional fields to the existing auth entry
            entry_tree:add(fvalid_user, account_range, account)
            entry_tree:add(fvalid_host, peer_range, peer)

        elseif n_authz == 3
        then
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)

            local peer_range = message_body
            peer, message_body = decodeString(peer_range, is_big_endian)
            local authority_range = message_body
            authority, message_body = decodeString(authority_range, is_big_endian)
            local account_range = message_body
            account, message_body = decodeString(account_range, is_big_endian)

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
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvsServerValidateDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local VALIDATION_HEADER_LEN = 7

    if message_body:len() >= VALIDATION_HEADER_LEN then
        -- Parse header: 4 bytes buffer size, 2 bytes introspection size, 1 byte flags
        local bsize = getUint(message_body(0,4), is_big_endian)
        local isize = getUint(message_body(4,2), is_big_endian)
        local flags = message_body(6,1):uint()
        tree:add(fvalid_bsize, message_body(0,4), bsize)
        tree:add(fvalid_isize, message_body(4,2), isize)
        tree:add(fvalid_azflg, message_body(6,1), flags)

        -- Parse all strings into a table first
        if message_body:len() > VALIDATION_HEADER_LEN then
            local remaining = message_body(VALIDATION_HEADER_LEN)
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
        tree:add(fbody, message_body)
    end
end

----------------------------------------------
-- pvaClientCreateChannelDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientCreateChannelDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local n_pvs = getUint32(message_body, is_big_endian)
    message_body = message_body(2)

    for i=0, n_pvs -1 do
        local cid = getUint64(message_body, is_big_endian)
        tree:add(fsearch_cid, message_body(0,4), cid)
        local name
        name, message_body = decodeString(message_body(4), is_big_endian)
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
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerCreateChannelDecoder (message_body, pkt, tree, is_big_endian)
    local cid = getUint64(message_body, is_big_endian)
    local sid = getUint64(message_body(4), is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fcid, message_body(0,4), cid)
    tree:add(fsid, message_body(4,4), sid)
    decodeStatus(message_body(8), tree, is_big_endian)
end

----------------------------------------------
-- pvaDestroyChannelDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaDestroyChannelDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local cid = getUint64(message_body, is_big_endian)
    local sid = getUint64(message_body(4), is_big_endian)
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fsid, message_body(0,4), sid)
    tree:add(fcid, message_body(4,4), cid)
end

----------------------------------------------
-- pvaClientDestroyDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaClientDestroyDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local command_name = application_messages[cmd]
    local sid = getUint64(message_body, is_big_endian)
    local ioid = getUint64(message_body, is_big_endian)
    tree:add(fsid, message_body(0,4), sid)
    tree:add(fioid, message_body(4,4), ioid)
    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u), ", command_name, sid, ioid))
end

----------------------------------------------
-- pvaGenericClientOpDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericClientOpDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local GENERIC_COMMAND_HEADER = 9
    if message_body:len() >= GENERIC_COMMAND_HEADER then
        local cname = application_messages[cmd]
        local sid = getUint64(message_body, is_big_endian)
        local ioid = getUint64(message_body, is_big_endian)
        local raw_sub_command = message_body(8, 1)
        local sub_command = raw_sub_command:uint()
        tree:add(fsid, message_body(0, 4), sid)
        tree:add(fioid, message_body(4, 4), ioid)
        local sub_tree = tree:add(fsubcmd, message_body(8, 1), sub_command)
        sub_tree:add(fsubcmd_proc, raw_sub_command, sub_command)
        sub_tree:add(fsubcmd_init, raw_sub_command, sub_command)
        sub_tree:add(fsubcmd_dstr, raw_sub_command, sub_command)
        sub_tree:add(fsubcmd_get, raw_sub_command, sub_command)
        sub_tree:add(fsubcmd_gtpt, raw_sub_command, sub_command)

        if ( message_body:len() > GENERIC_COMMAND_HEADER ) then
            message_body = message_body:range(GENERIC_COMMAND_HEADER)

            -- if the subcommand is 0x00 (DATA) then we need to get the change BitSet
            if sub_command == 0x00 then
                -- take the next byte as a count followed by that many bytes of the bitset
                local bitset_count
                bitset_count, message_body = decodeSize(message_body, is_big_endian)
                local bitset = message_body:range(0, bitset_count)

                -- Process remaining payload
                if message_body and message_body:len() > 0 then
                    pvaDecodePVData(message_body, tree, is_big_endian, ioid, bitset)
                end
            elseif sub_command == 0x08 then
                -- MONITOR INIT
                if message_body:len() > 0 then
                    pvaDecodeMonitorInit(message_body, tree, is_big_endian, ioid)
                end
            else
                if message_body:len() > 0 then
                    pvaDecodePVData(message_body, tree, is_big_endian, ioid)
                end
            end
        end

        pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u, sub=%02x), ", cname, sid, ioid, sub_command))
    end
end


----------------------------------------------
-- pvaGenericServerOpDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericServerOpDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local GENERIC_COMMAND_HEADER = 5
    local cname = application_messages[cmd]
    local ioid = getUint64(message_body, is_big_endian)
    local raw_sub_command = message_body(4,1)
    local sub_command = raw_sub_command:uint()

    -- Add fields to tree
    tree:add(fioid, message_body(0,4), ioid)
    local sub_tree = tree:add(fsubcmd, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_proc, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_init, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_dstr, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_get, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_gtpt, raw_sub_command, sub_command)

    if ( message_body:len() > GENERIC_COMMAND_HEADER ) then
        -- Skip the header
        message_body = message_body(GENERIC_COMMAND_HEADER):tvb()

        -- if the subcommand is 0x00 (DATA) then we need to get the change BitSet
        if sub_command == 0x00 then
            -- take the next byte as a count followed by that many bytes of the bitset
            local bitset_count
            bitset_count, message_body = decodeSize(message_body, is_big_endian)
            local bitset = message_body:range(0,bitset_count)

            -- Process remaining payload
            if message_body and message_body:len() > 0 then
                pvaDecodePVData(message_body, tree, is_big_endian, ioid, bitset)
            end
        elseif sub_command == 0x08 then
            -- MONITOR INIT - handle status then introspection data
            if cmd == MONITOR_MESSAGE then
                message_body = decodeStatus(message_body, tree, is_big_endian)
            end

            -- Process introspection data
            if message_body and message_body:len() > 0 then
                pvaDecodeMonitorInit(message_body, tree, is_big_endian, ioid)
            end
        else
            -- Status handling: All messages except MONITOR UPDATE have status
            local is_monitor_update = cmd == MONITOR_MESSAGE and bit.band(sub_command, 0x08) == 0
            if not is_monitor_update then
                message_body = decodeStatus(message_body, tree, is_big_endian)
            end

            -- Process remaining payload
            if message_body and message_body:len() > 0 then
                pvaDecodePVData(message_body, tree, is_big_endian, ioid)
            end
        end
    end

    pkt.cols.info:append(string.format("cmd=%02x %s(ioid=%u, sub=%02x)", cmd , cname, ioid, sub_command))
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

    local message_body = buf(PVA_HEADER_LEN, message_len);
    if is_ctrl_cmd == 0
    then
        -- application message
        if bit.band(flags_val, 0x40) ~= 0
        then
            -- server
            local cmd_handler = server_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(message_body, pkt, header_tree_node, is_big_endian ~= 0, cmd)
                show_generic_cmd = 0
            end
        else
            -- client
            local cmd_handler = client_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(message_body, pkt, header_tree_node, is_big_endian ~= 0, cmd)
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
            header_tree_node:add(fpvd, buf(8, message_len))
        else
            header_tree_node:addle(fpvd, buf(8, message_len))
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
