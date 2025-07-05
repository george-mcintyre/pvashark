-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- Copyright 2021 Michael Davidsaver, 2025 George McIntyre
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
io.stderr:write("Loading PVA...\n")

local pva = Proto("pva", "Process Variable Access")

-- application messages
local bcommands = {
    [0] = "BEACON",
    [1] = "CONNECTION_VALIDATION",
    [2] = "ECHO",
    [3] = "SEARCH",
    [4] = "SEARCH_RESPONSE",
    [5] = "AUTHNZ",
    [6] = "ACL_CHANGE",
    [7] = "CREATE_CHANNEL",
    [8] = "DESTROY_CHANNEL",
    [9] = "CONNECTION_VALIDATED",
    [10] = "GET",
    [11] = "PUT",
    [12] = "PUT_GET",
    [13] = "MONITOR",
    [14] = "ARRAY",
    [15] = "DESTROY_REQUEST",
    [16] = "PROCESS",
    [17] = "GET_FIELD",
    [18] = "MESSAGE",
    [19] = "MULTIPLE_DATA",
    [20] = "RPC",
    [21] = "CANCEL_REQUEST",
    [22] = "ORIGIN_TAG",
}

-- control messages
local bctrlcommands = {
    [0] = "MARK_TOTAL_BYTES_SENT",
    [1] = "ACK_TOTAL_BYTES_RECEIVED",
    [2] = "SET_BYTE_ORDER",
}

local stscodes = {
    [0xff] = "OK",
    [0] = "OK",
    [1] = "Warning",
    [2] = "Error",
    [3] = "Fatal Error",
}

-- PVXS TypeCodes (from src/pvxs/data.h)
local TYPE_CODE_BOOLEAN = 0x00;

local TYPE_CODE_BYTE = 0x20;
local TYPE_CODE_SHORT = 0x21;
local TYPE_CODE_INT = 0x22;
local TYPE_CODE_LONG = 0x23;

local TYPE_CODE_UBYTE = 0x24;
local TYPE_CODE_USHORT = 0x25;
local TYPE_CODE_UINT = 0x26;
local TYPE_CODE_ULONG = 0x27;

local TYPE_CODE_FLOAT = 0x42;
local TYPE_CODE_DOUBLE = 0x43; 

local TYPE_CODE_STRING = 0x60;

local TYPE_CODE_STRUCT = 0x80;
local TYPE_CODE_UNION = 0x81;
local TYPE_CODE_ANY = 0x82;

-- Array TypeCodes
local TYPE_CODE_BOOLEAN_ARRAY = 0x08;

local TYPE_CODE_BYTE_ARRAY = 0x28;
local TYPE_CODE_SHORT_ARRAY = 0x29;
local TYPE_CODE_INT_ARRAY = 0x2A;
local TYPE_CODE_LONG_ARRAY = 0x2B;

local TYPE_CODE_UBYTE_ARRAY = 0x2C;
local TYPE_CODE_USHORT_ARRAY = 0x2D;
local TYPE_CODE_UINT_ARRAY = 0x2E;
local TYPE_CODE_ULONG_ARRAY = 0x2F;

local TYPE_CODE_FLOAT_ARRAY = 0x4A;
local TYPE_CODE_DOUBLE_ARRAY = 0x4B; 

local TYPE_CODE_STRING_ARRAY = 0x68;

local TYPE_CODE_STRUCT_ARRAY = 0x88;
local TYPE_CODE_UNION_ARRAY = 0x89;
local TYPE_CODE_ANY_ARRAY = 0x8A;

-- Cache and special codes
local CACHE_STORE_CODE = 0xFD;
local CACHE_FETCH_CODE = 0xFE;
local TYPE_CODE_NULL = 0xFF;

-- Legacy codes (not in PVXS specification)
local TYPE_CODE_INTROSPECTION_ONLY = 0x01;

-- TypeCode to name mapping table
local PVD_TYPES = {
    [TYPE_CODE_BOOLEAN] = "bool",
    [TYPE_CODE_BYTE] = "int8_t",
    [TYPE_CODE_SHORT] = "int16_t", 
    [TYPE_CODE_INT] = "int32_t",
    [TYPE_CODE_LONG] = "int64_t",
    [TYPE_CODE_UBYTE] = "uint8_t",
    [TYPE_CODE_USHORT] = "uint16_t",
    [TYPE_CODE_UINT] = "uint32_t", 
    [TYPE_CODE_ULONG] = "uint64_t",
    [TYPE_CODE_FLOAT] = "float",
    [TYPE_CODE_DOUBLE] = "double",
    [TYPE_CODE_STRING] = "string",
    [TYPE_CODE_STRUCT] = "struct",
    [TYPE_CODE_UNION] = "union",
    [TYPE_CODE_ANY] = "any",
    
    -- Array types
    [TYPE_CODE_BOOLEAN_ARRAY] = "bool[]",
    [TYPE_CODE_BYTE_ARRAY] = "int8_t[]",
    [TYPE_CODE_SHORT_ARRAY] = "int16_t[]",
    [TYPE_CODE_INT_ARRAY] = "int32_t[]",
    [TYPE_CODE_LONG_ARRAY] = "int64_t[]",
    [TYPE_CODE_UBYTE_ARRAY] = "uint8_t[]",
    [TYPE_CODE_USHORT_ARRAY] = "uint16_t[]",
    [TYPE_CODE_UINT_ARRAY] = "uint32_t[]",
    [TYPE_CODE_ULONG_ARRAY] = "uint64_t[]",
    [TYPE_CODE_FLOAT_ARRAY] = "float[]",
    [TYPE_CODE_DOUBLE_ARRAY] = "double[]",
    [TYPE_CODE_STRING_ARRAY] = "string[]",
    [TYPE_CODE_STRUCT_ARRAY] = "struct[]",
    [TYPE_CODE_UNION_ARRAY] = "union[]",
    [TYPE_CODE_ANY_ARRAY] = "any[]",
    
    -- Special/cache codes
    [CACHE_STORE_CODE] = "cache_store",
    [CACHE_FETCH_CODE] = "cache_fetch", 
    [TYPE_CODE_NULL] = "null",
    [TYPE_CODE_INTROSPECTION_ONLY] = "introspectionOnly"
}

local placeholder= ProtoField.bytes("pva.placeholder", " ")

local fmagic= ProtoField.uint8("pva.magic", "Magic", base.HEX)
local fver  = ProtoField.uint8("pva.version", "Version", base.DEC)
local fflags= ProtoField.uint8("pva.flags", "Flags", base.HEX)
local fflag_dir = ProtoField.uint8("pva.direction", "Direction", base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end = ProtoField.uint8("pva.endian", "Byte order", base.HEX, {[0]="LSB",[1]="MSB"}, 0x80)
local fflag_msgtype = ProtoField.uint8("pva.msg_type", "Message type", base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented = ProtoField.uint8("pva.segmented", "Segmented", base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd  = ProtoField.uint8("pva.command", "Command", base.HEX, bcommands)
local fctrlcmd  = ProtoField.uint8("pva.ctrlcommand", "Control Command", base.HEX, bctrlcommands)
local fctrldata  = ProtoField.uint32("pva.ctrldata", "Control Data", base.HEX)
local fsize = ProtoField.uint32("pva.size", "Size", base.DEC)
local fbody = ProtoField.bytes("pva.body", "Body")
local fpvd = ProtoField.bytes("pva.pvd", "PVData Body")
local fguid = ProtoField.bytes("pva.guid", "GUID")

-- PVData Fields
local fpvd_struct = ProtoField.bytes("pva.pvd_struct", "PVStructure")
local fpvd_field = ProtoField.bytes("pva.pvd_field", "Field")
local fpvd_field_name = ProtoField.string("pva.pvd_field_name", "Field Name")
local fpvd_type = ProtoField.uint8("pva.pvd_type", "Type", base.HEX)
local fpvd_value = ProtoField.bytes("pva.pvd_value", "Value")
local fpvd_introspection = ProtoField.bytes("pva.pvd_introspection", "Introspection Data")
local fpvd_debug = ProtoField.bytes("pva.pvd_debug", "Debug Info")

-- common
local fcid = ProtoField.uint32("pva.cid", "Client Channel ID")
local fsid = ProtoField.uint32("pva.sid", "Server Channel ID")
local fioid = ProtoField.uint32("pva.ioid", "Operation ID")
local fsubcmd = ProtoField.uint8("pva.subcmd", "Sub-command", base.HEX)
local fsubcmd_proc = ProtoField.uint8("pva.process", "Process", base.HEX, {[0]="",[1]="Yes"}, 0x04)
local fsubcmd_init = ProtoField.uint8("pva.init",    "Init   ", base.HEX, {[0]="",[1]="Yes"}, 0x08)
local fsubcmd_dstr = ProtoField.uint8("pva.destroy", "Destroy", base.HEX, {[0]="",[1]="Yes"}, 0x10)
local fsubcmd_get  = ProtoField.uint8("pva.get",     "Get    ", base.HEX, {[0]="",[1]="Yes"}, 0x40)
local fsubcmd_gtpt = ProtoField.uint8("pva.getput",  "GetPut ", base.HEX, {[0]="",[1]="Yes"}, 0x80)
local fstatus = ProtoField.uint8("pva.status", "Status", base.HEX, stscodes)

-- For BEACON

local fbeacon_seq = ProtoField.uint8("pva.bseq", "Beacon sequence#")
local fbeacon_change = ProtoField.uint16("pva.change", "Beacon change count")

-- For CONNECTION_VALIDATION

local fvalid_bsize = ProtoField.uint32("pva.qsize", "Client Queue Size")
local fvalid_isize = ProtoField.uint16("pva.isize", "Client Introspection registery size")
local fvalid_qos = ProtoField.uint16("pva.qos", "Client QoS", base.HEX)
local fvalid_method = ProtoField.string("pva.method", "AuthZ method")
local fvalid_azflg  = ProtoField.uint8 ("pva.authzflag","AuthZ Flags",  base.HEX)
local fvalid_azcnt  = ProtoField.uint8 ("pva.authzcnt", "AuthZ Elem‑cnt",base.DEC)

-- For AUTHZ_REQUEST

local fauthz_request = ProtoField.string("pva.authzrequest", "AuthZ request")
local fvalid_host = ProtoField.string("pva.host", "AuthZ host")
local fvalid_authority = ProtoField.string("pva.authority", "AuthZ authority")
local fvalid_user = ProtoField.string("pva.user", "AuthZ name")
local fvalid_account = ProtoField.string("pva.account", "AuthZ account")
local fvalid_isTLS = ProtoField.uint8("pva.isTLS", "AuthZ isTLS")

-- For AUTHZ_RESPONSE

local fauthz_response = ProtoField.string("pva.authzresponse", "AuthZ response")

-- For AuthZ Entry Array (removed fauth_entry_index as no longer needed)

-- For SEARCH
local fsearch_seq = ProtoField.uint32("pva.seq", "Search Sequence #")
local fsearch_addr = ProtoField.bytes("pva.addr", "Address")
local fsearch_port = ProtoField.uint16("pva.port", "Port")
local fsearch_mask = ProtoField.uint8("pva.mask", "Mask", base.HEX)
local fsearch_mask_repl  = ProtoField.uint8("pva.reply", "Reply", base.HEX, {[0]="Optional",[1]="Required"}, 0x01)
local fsearch_mask_bcast = ProtoField.uint8("pva.ucast", "Reply", base.HEX, {[0]="Broadcast",[1]="Unicast"}, 0x80)
local fsearch_proto = ProtoField.string("pva.proto", "Transport Protocol")
local fsearch_count = ProtoField.uint16("pva.count", "PV Count")
local fsearch_cid = ProtoField.uint32("pva.cid", "CID")
local fsearch_name = ProtoField.string("pva.pv", "Name")

-- For SEARCH_RESPONSE
local fsearch_found = ProtoField.bool("pva.found", "Found")

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

local specials_server
local specials_client

local function decode (buf, pkt, root)
  if buf:len()<8 then return 0 end
  -- [0xCA, ver, flags, cmd, size[4]]

  if buf(0,1):uint()~=0xca
  then
    pkt.cols.info:append("Corrupt message.  Bad magic.")
    return 0;
  end

  local flagval = buf(2,1):uint()
  local isbe = bit.band(flagval, 0x80)
  local ctrlcmd = bit.band(flagval, 0x01)
  local msglen
  if ctrlcmd==0
  then
    if isbe~=0
    then
      msglen = buf(4,4):uint()
    else
      msglen = buf(4,4):le_uint()
    end
  else
    -- control message len is always 0 (only header), size holds data
    msglen = 0
  end

  if buf:len()<8+msglen
  then
    return (buf:len()-(8+msglen))
  end

  local t = root:add(pva, buf(0,8+msglen))

  t:add(fmagic, buf(0,1))
  t:add(fver, buf(1,1))
  local flags = t:add(fflags, buf(2,1))
  if ctrlcmd==0
  then
    t:add(fcmd, buf(3,1))
    t:add(fsize, buf(4,4), msglen)
  else
    t:add(fctrlcmd, buf(3,1))
    t:add(fctrldata, buf(4,4))
  end

  flags:add(fflag_msgtype, buf(2,1))
  flags:add(fflag_segmented, buf(2,1))
  flags:add(fflag_dir, buf(2,1))
  flags:add(fflag_end, buf(2,1))

  local cmd = buf(3,1):uint()
  local showgeneric = 1

  if ctrlcmd==0
  then
    -- application message
    if bit.band(flagval, 0x40)~=0
    then
        -- server

        local spec = specials_server[cmd]
        if spec
        then
            spec(buf(8,msglen), pkt, t, isbe~=0, cmd)
            showgeneric = 0
        end
    else
        -- client

        local spec = specials_client[cmd]
        if spec
        then
            spec(buf(8,msglen), pkt, t, isbe~=0, cmd)
            showgeneric = 0
        end
    end
  else
    -- control message
    local cmd_name = bctrlcommands[cmd]
    if cmd_name
    then
      pkt.cols.info:append(cmd_name..", ")
    else
      pkt.cols.info:append("Msg: "..cmd.." ")
    end
    showgeneric = 0
  end

  if showgeneric~=0
  then
    local cmd_name = bcommands[cmd]
    if cmd_name
    then
      pkt.cols.info:append(cmd_name..", ")
    else
      pkt.cols.info:append("Msg: "..cmd.." ")
    end

    if isbe
    then
      t:add(fbody, buf(8, msglen))
    else
      t:addle(fbody, buf(8, msglen))
    end
  end

  return 8+msglen
end

function pva.dissector (buf, pkt, root)

  if buf(0,1):uint()~=0xca
  then
      return
  end

  pkt.cols.protocol = pva.name
  pkt.cols.info:clear()
  pkt.cols.info:append(pkt.src_port.." -> "..pkt.dst_port.." ")
  if bit.band(buf(2,1):uint(), 0x40)~=0
  then
    pkt.cols.info:append("Server ")
  else
    pkt.cols.info:append("Client ")
  end

  local origbuf = buf
  local totalconsumed = 0

  --print(pkt.number.." "..buf:len())

  -- wireshark 1.99.2 introduced dissect_tcp_pdus() to do this for us
  while buf:len()>0
  do
    local consumed = decode(buf,pkt,root)
    --print("Consumed "..consumed)

    if consumed<0
    then
      -- Wireshark documentation lists this as the prefered was
      -- to indicate TCP reassembly.  However, as of version 1.2.11
      -- this does not work for LUA disectors.  However, the pinfo
      -- mechanism does.
      --return consumed
      pkt.desegment_offset = totalconsumed
      pkt.desegment_len = -consumed
      return
    elseif consumed<8
    then
      pkt.cols.info:preppend("[Incomplete] ")
      break
    else
      --print("Consuming "..consumed)
      totalconsumed = totalconsumed + consumed
      buf=buf(consumed):tvb()
    end
  end
end

local utbl = DissectorTable.get("udp.port")
utbl:add(5075, pva)
utbl:add(5076, pva)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5075, pva)
DissectorTable.get("tls.alpn"):add("pva/1", pva)


local function decodeSize(buf, isbe)
    if buf:len() < 1 then
        return 0, buf
    end

    local s0 = buf(0,1):uint()
    if s0==255 then
        return 0, buf:len() > 1 and buf(1) or buf -- special nil string? treat as zero
    elseif s0==254 then
        if buf:len() < 5 then
            return 0, buf
        end
        if isbe then
            return buf(1,4):uint(), buf(5)
        else
            return buf(1,4):le_uint(), buf(5)
        end
    else
        return s0, buf:len() > 1 and buf(1) or buf
    end
end

-- extract a string and return that string, and the remaining buffer
local function decodeString(buf, isbe)
    if buf:len() == 0 then
        return buf(0,0), nil
    end

    local s, remaining_buf = decodeSize(buf, isbe)

    -- Check if we have enough bytes for the string
    if not remaining_buf or remaining_buf:len() < s then
        -- Not enough data, return what we have
        return buf(0, math.min(s, buf:len())), nil
    end

    if s == remaining_buf:len() then
        return remaining_buf(0,s), nil
    else
        return remaining_buf(0,s), remaining_buf(s)
    end
end


-- skip a label string and return the remaining buffer
local function skipPVStructureLabelString(buf, isbe)
    local s, buf = decodeSize(buf, isbe)
    if s==buf:len() then
        return nil
    else
        return buf(s+1)
    end
end



-- Helper function to read PVData size (Phase 2)
local function readPVSize(buf, offset, isbe)
    if not buf or offset >= buf:len() then
        return 0, offset
    end

    local size_byte = buf(offset, 1):uint()
    if size_byte < 0xFE then
        return size_byte, offset + 1
    elseif size_byte == 0xFE then
        if offset + 2 >= buf:len() then return 0, offset end
        local size = isbe and buf(offset + 1, 2):uint() or buf(offset + 1, 2):le_uint()
        return size, offset + 3
    elseif size_byte == 0xFF then
        if offset + 4 >= buf:len() then return 0, offset end
        local size = isbe and buf(offset + 1, 4):uint() or buf(offset + 1, 4):le_uint()
        return size, offset + 5
    end
    return 0, offset
end

-- Helper function to read PVData string (Phase 2)
local function readPVString(buf, offset, isbe)
    local str_len, new_offset = readPVSize(buf, offset, isbe)
    if str_len == 0 or new_offset + str_len > buf:len() then
        return "", new_offset
    end
    local str = buf(new_offset, str_len):string()
    return str, new_offset + str_len
end

-- PVData field parser (Phase 2) - Full featured with API fixes
local function parsePVField(buf, offset, isbe, tree, depth)
    if offset >= buf:len() or depth > 10 then
        return offset
    end

    local type_byte = buf(offset, 1):uint()
    local type_name = PVD_TYPES[type_byte] or string.format("unknown(0x%02X)", type_byte)

    -- Create field subtree with proper API
    local field_tree = tree:add(fpvd_field, buf(offset, 1), string.format("Field [%s] (0x%02X)", type_name, type_byte))
    offset = offset + 1

    -- Handle different field types
    if type_byte == TYPE_CODE_STRUCT then -- struct
        if offset < buf:len() then
            local field_count, new_offset = readPVSize(buf, offset, isbe)
            field_tree:append_text(string.format(" (%d fields)", field_count))
            offset = new_offset

            -- Sanity check field count
            if field_count > 50 then
                field_tree:append_text(" [Warning: High field count, limiting to 20]")
                field_count = 20 -- Limit to prevent runaway parsing
            end

            -- Parse field names and types
            for i = 1, field_count do
                if offset >= buf:len() then
                    field_tree:append_text(" [Error: Unexpected end of buffer]")
                    break
                end

                -- Read field name
                local field_name, name_offset = readPVString(buf, offset, isbe)
                if field_name and field_name ~= "" then
                    local name_len = name_offset - offset
                    if name_len > 0 and name_len <= buf:len() - offset then
                        field_tree:add(fpvd_field_name, buf(offset, name_len), field_name)
                    end
                end
                offset = name_offset

                -- Recursively parse field type
                offset = parsePVField(buf, offset, isbe, field_tree, depth + 1)
            end
        end

    elseif type_byte == TYPE_CODE_UNION then -- union
        if offset < buf:len() then
            local union_name, name_offset = readPVString(buf, offset, isbe)
            if union_name and union_name ~= "" then
                field_tree:append_text(string.format(" [%s]", union_name))
                local name_len = name_offset - offset
                if name_len > 0 and name_len <= buf:len() - offset then
                    field_tree:add(fpvd_field_name, buf(offset, name_len), union_name)
                end
                offset = name_offset

                -- Parse union fields (similar to structure)
                if offset < buf:len() then
                    local field_count, new_offset = readPVSize(buf, offset, isbe)
                    field_tree:append_text(string.format(" (%d fields)", field_count))
                    offset = new_offset

                    -- Limit field count
                    if field_count > 50 then
                        field_count = 20
                    end

                    for i = 1, field_count do
                        if offset >= buf:len() then break end

                        -- Read field name
                        local field_name, name_offset = readPVString(buf, offset, isbe)
                        if field_name and field_name ~= "" then
                            field_tree:add(fpvd_field_name, buf(offset, name_len), field_name)
                        end
                        offset = name_offset

                        -- Recursively parse field type
                        offset = parsePVField(buf, offset, isbe, field_tree, depth + 1)
                    end
                end
            end
        end

    elseif type_byte == CACHE_STORE_CODE then -- cache store: 0xFD key FieldDesc
        if offset < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            offset = offset + 2
            
            -- Use simplified cache store format
            field_tree:set_text(string.format("cache_%d (0x%02X: struct)", cache_key, TYPE_CODE_STRUCT))
            
            -- Parse the following FieldDesc tree
            if offset < buf:len() then
                offset = parsePVField(buf, offset, isbe, field_tree, depth + 1)
            end
        end
        
    elseif type_byte == CACHE_FETCH_CODE then -- cache fetch: 0xFE key
        if offset < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            field_tree:set_text(string.format("Cache Fetch %d", cache_key))
            offset = offset + 2
        end

    elseif type_byte == TYPE_CODE_BOOLEAN then -- bool
        field_tree:append_text(" (bool type)")
    elseif type_byte >= TYPE_CODE_BYTE and type_byte <= TYPE_CODE_ULONG then -- integer types
        field_tree:append_text(string.format(" (%s type)", type_name))
    elseif type_byte == TYPE_CODE_FLOAT or type_byte == TYPE_CODE_DOUBLE then -- float types
        field_tree:append_text(string.format(" (%s type)", type_name))
    elseif type_byte == TYPE_CODE_STRING then -- string
        field_tree:append_text(" (string type)")
    elseif type_byte == TYPE_CODE_ANY then -- any
        field_tree:append_text(" (any type)")
    elseif type_byte == TYPE_CODE_BOOLEAN_ARRAY or (type_byte >= TYPE_CODE_BYTE_ARRAY and type_byte <= TYPE_CODE_ULONG_ARRAY) or 
           type_byte == TYPE_CODE_FLOAT_ARRAY or type_byte == TYPE_CODE_DOUBLE_ARRAY or type_byte == TYPE_CODE_STRING_ARRAY or
           (type_byte >= TYPE_CODE_STRUCT_ARRAY and type_byte <= TYPE_CODE_ANY_ARRAY) then -- array types
        field_tree:append_text(string.format(" (%s type)", type_name))
    else
        field_tree:append_text(string.format(" (unhandled type 0x%02X)", type_byte))
    end

    return offset
end

-- Enhanced PVA size decoder for variable-length encoding
local function readPVASize(buf, offset, isbe)
    if not buf or offset >= buf:len() then
        return 0, offset
    end

    local size_byte = buf(offset, 1):uint()

    if size_byte < 0xFE then
        -- Single byte size (0-253)
        return size_byte, offset + 1
    elseif size_byte == 0xFE then
        -- Two-byte size (254-65535)
        if offset + 2 >= buf:len() then return 0, offset end
        local size = isbe and buf(offset + 1, 2):uint() or buf(offset + 1, 2):le_uint()
        return size, offset + 3
    elseif size_byte == 0xFF then
        -- Four-byte size (65536+)
        if offset + 4 >= buf:len() then return 0, offset end
        local size = isbe and buf(offset + 1, 4):uint() or buf(offset + 1, 4):le_uint()
        return size, offset + 5
    end

    return 0, offset
end

-- Enhanced string decoder with proper size handling
local function readPVAString(buf, offset, isbe, tree, label)
    local str_len, new_offset = readPVASize(buf, offset, isbe)
    if str_len == 0 or new_offset + str_len > buf:len() then
        return "", new_offset
    end

    local str_data = buf(new_offset, str_len):string()

    -- Add to tree if provided
    if tree then
        local str_tree = tree:add(buf(offset, new_offset - offset + str_len),
                                 string.format("%s: \"%s\"", label or "String", str_data))
        if new_offset - offset > 1 then
            str_tree:add(buf(offset, new_offset - offset), string.format("Length: %d", str_len))
        end
        str_tree:add(buf(new_offset, str_len), string.format("Value: \"%s\"", str_data))
    end

    return str_data, new_offset + str_len
end

-- Recursive field parser for structures and unions
local function parseField(buf, offset, isbe, tree, depth)
    if not buf or offset >= buf:len() or depth > 10 then
        return offset
    end

    local field_type = buf(offset, 1):uint()
    local type_name = PVD_TYPES[field_type] or string.format("unknown(0x%02X)", field_type)
    offset = offset + 1

    -- Handle nil tree gracefully - just advance offset without adding to tree
    local field_tree = tree and tree:add(buf(offset - 1, 1), string.format("Field Type: %s (0x%02X)", type_name, field_type)) or nil

    if field_type == TYPE_CODE_STRUCT then -- struct
        local field_count, new_offset = readPVASize(buf, offset, isbe)
        if field_tree then field_tree:append_text(string.format(" - %d fields", field_count)) end
        offset = new_offset

        -- Parse field names and types
        for i = 1, math.min(field_count, 20) do -- Limit to prevent runaway
            if offset >= buf:len() then break end

            -- Read field name
            local field_name, name_offset = readPVAString(buf, offset, isbe, field_tree, field_tree and string.format("Field %d Name", i) or nil)
            offset = name_offset

            -- Recursively parse field type
            offset = parseField(buf, offset, isbe, field_tree, depth + 1)
        end

    elseif field_type == TYPE_CODE_UNION then -- union
        -- Read union name first
        local union_name, name_offset = readPVAString(buf, offset, isbe, field_tree, field_tree and "Union Name" or nil)
        offset = name_offset

        if union_name ~= "" and field_tree then
            field_tree:append_text(string.format(" \"%s\"", union_name))
        end

        -- Parse union fields
        local field_count, new_offset = readPVASize(buf, offset, isbe)
        if field_tree then field_tree:append_text(string.format(" - %d choices", field_count)) end
        offset = new_offset

        -- Parse choice names and types
        for i = 1, math.min(field_count, 20) do
            if offset >= buf:len() then break end

            local choice_name, name_offset = readPVAString(buf, offset, isbe, field_tree, field_tree and string.format("Choice %d Name", i) or nil)
            offset = name_offset

            offset = parseField(buf, offset, isbe, field_tree, depth + 1)
        end

    elseif field_type == CACHE_STORE_CODE then -- cache store: 0xFD key FieldDesc
        if offset < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            offset = offset + 2
            
            -- Use simplified cache store format
            
            -- Parse the following FieldDesc tree
            if offset < buf:len() then
                offset = parseField(buf, offset, isbe, field_tree, depth + 1)
            end
        end
        
    elseif field_type == CACHE_FETCH_CODE then -- cache fetch: 0xFE key
        if offset < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            if field_tree then field_tree:set_text(string.format("Cache Fetch %d", cache_key)) end
            offset = offset + 2
        end

    elseif field_type == TYPE_CODE_STRING then -- string
        if field_tree then field_tree:append_text(" (string type)") end

    elseif field_type >= TYPE_CODE_BYTE and field_type <= TYPE_CODE_ULONG then -- integer types
        if field_tree then field_tree:append_text(string.format(" (%s type)", type_name)) end
    elseif field_type == TYPE_CODE_FLOAT or field_type == TYPE_CODE_DOUBLE then -- float types
        if field_tree then field_tree:append_text(string.format(" (%s type)", type_name)) end
    elseif field_type == TYPE_CODE_ANY then -- any
        if field_tree then field_tree:append_text(" (any type)") end
    elseif field_type == TYPE_CODE_BOOLEAN_ARRAY or (field_type >= TYPE_CODE_BYTE_ARRAY and field_type <= TYPE_CODE_ULONG_ARRAY) or 
           field_type == TYPE_CODE_FLOAT_ARRAY or field_type == TYPE_CODE_DOUBLE_ARRAY or field_type == TYPE_CODE_STRING_ARRAY or
           (field_type >= TYPE_CODE_STRUCT_ARRAY and field_type <= TYPE_CODE_ANY_ARRAY) then -- array types
        if field_tree then field_tree:append_text(string.format(" (%s type)", type_name)) end

    else
        if field_tree then field_tree:append_text(string.format(" (type 0x%02X)", field_type)) end
    end

    return offset
end

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

-- Enhanced value parser with Phase 4 features
local function parseValue(buf, offset, field_type, isbe, tree, field_name)
    if not buf or offset >= buf:len() then
        return offset
    end

    local type_name = PVD_TYPES[field_type] or "unknown"

    if field_type == TYPE_CODE_BOOLEAN then -- bool
        if offset < buf:len() then
            local value = buf(offset, 1):uint()
            tree:add(buf(offset, 1), string.format("%s: %s (bool)", field_name, value == 0 and "false" or "true"))
            return offset + 1
        end

    elseif field_type == TYPE_CODE_BYTE then -- int8_t
        if offset < buf:len() then
            local value = buf(offset, 1):int()
            tree:add(buf(offset, 1), string.format("%s: %d (0x%02X) (int8_t)", field_name, value, value))
            return offset + 1
        end

    elseif field_type == TYPE_CODE_SHORT then -- int16_t
        if offset + 1 < buf:len() then
            local value = isbe and buf(offset, 2):int() or buf(offset, 2):le_int()
            tree:add(buf(offset, 2), string.format("%s: %d (int16_t)", field_name, value))
            return offset + 2
        end

    elseif field_type == TYPE_CODE_INT then -- int32_t
        if offset + 3 < buf:len() then
            local value = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
            tree:add(buf(offset, 4), string.format("%s: %d (int32_t)", field_name, value))
            return offset + 4
        end

    elseif field_type == TYPE_CODE_LONG then -- int64_t (enhanced timestamp support)
        if offset + 7 < buf:len() then
            local value = isbe and buf(offset, 8):int64() or buf(offset, 8):le_int64()
            local value_num = tonumber(tostring(value))

            -- Special formatting for timestamp fields
            if field_name:match("time") or field_name:match("Time") or field_name:match("seconds") then
                local formatted_time = formatEpicsTimestamp(value_num, 0)
                tree:add(buf(offset, 8), string.format("%s: %s (%s) (int64_t)", field_name, tostring(value), formatted_time))
            else
                tree:add(buf(offset, 8), string.format("%s: %s (int64_t)", field_name, tostring(value)))
            end
            return offset + 8
        end

    elseif field_type == TYPE_CODE_FLOAT then -- float
        if offset + 3 < buf:len() then
            local value = isbe and buf(offset, 4):float() or buf(offset, 4):le_float()
            tree:add(buf(offset, 4), string.format("%s: %.6g (float)", field_name, value))
            return offset + 4
        end

    elseif field_type == TYPE_CODE_DOUBLE then -- double
        if offset + 7 < buf:len() then
            local value = isbe and buf(offset, 8):float() or buf(offset, 8):le_float()
            tree:add(buf(offset, 8), string.format("%s: %.6g (double)", field_name, value))
            return offset + 8
        end

    elseif field_type == TYPE_CODE_STRING then -- string (enhanced)
        local str_len, new_offset = readPVASize(buf, offset, isbe)
        if new_offset + str_len <= buf:len() then
            local str_value = str_len > 0 and buf(new_offset, str_len):string() or ""

            -- Special handling for common EPICS fields
            if field_name == "message" and str_value == "" then
                str_value = "<no alarm>"
            end

            tree:add(buf(offset, new_offset - offset + str_len), string.format("%s: \"%s\" (string, %d chars)", field_name, str_value, str_len))
            return new_offset + str_len
        end

    -- Phase 4: Array type support
    elseif field_type >= TYPE_CODE_BYTE_ARRAY and field_type <= TYPE_CODE_ULONG_ARRAY then -- Array types
        local element_type = field_type - TYPE_CODE_BOOLEAN_ARRAY -- Convert to element type
        local array_len, len_offset = readPVASize(buf, offset, isbe)

        if len_offset < buf:len() then
            local array_tree = tree:add(buf(offset), string.format("%s: [%d elements] (array)", field_name, array_len))
            offset = len_offset

            -- Parse first few elements
            for i = 1, math.min(array_len, 10) do -- Limit display to 10 elements
                if offset >= buf:len() then break end
                offset = parseValue(buf, offset, element_type, isbe, array_tree, string.format("[%d]", i-1))
            end

            if array_len > 10 then
                array_tree:add(buf(0, 0), string.format("... (%d more elements)", array_len - 10))
            end
        end

    else
        -- For unknown types, show raw bytes with better formatting
        local remaining = math.min(16, buf:len() - offset) -- Show max 16 bytes
        if remaining > 0 then
            local hex_str = ""
            for i = 0, remaining - 1 do
                hex_str = hex_str .. string.format("%02X ", buf(offset + i, 1):uint())
            end
            tree:add(buf(offset, remaining), string.format("%s: %s(type 0x%02X, %d bytes)", field_name, hex_str, field_type, remaining))
            return offset + remaining
        end
    end

    return offset
end

-- Enhanced union value parser with Phase 4 discriminator support
local function parseUnionValue(buf, offset, union_fields, isbe, tree, union_name)
    if not buf or offset >= buf:len() or #union_fields == 0 then
        return offset
    end

    -- Read union discriminator (which choice is active)
    local discriminator, disc_offset = readPVASize(buf, offset, isbe)

    if discriminator >= #union_fields then
        tree:add(buf(offset, disc_offset - offset), string.format("Invalid discriminator: %d (max %d)", discriminator, #union_fields - 1))
        return disc_offset
    end

    local active_field = union_fields[discriminator + 1]
    local disc_tree = tree:add(buf(offset, disc_offset - offset), string.format("Active Choice: %d (%s)", discriminator, active_field.name))
    offset = disc_offset

    -- Special handling for common EPICS union types
    if union_name == "alarm_t" then
        -- Parse alarm union with enhanced status decoding
        if active_field.name == "severity" and offset + 3 < buf:len() then
            local severity = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
            local sev_name, _ = decodeAlarmStatus(severity, 0)
            tree:add(buf(offset, 4), string.format("severity: %d (%s)", severity, sev_name))
            return offset + 4
        elseif active_field.name == "status" and offset + 3 < buf:len() then
            local status = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
            local _, stat_name = decodeAlarmStatus(0, status)
            tree:add(buf(offset, 4), string.format("status: %d (%s)", status, stat_name))
            return offset + 4
        end

    elseif union_name == "time_t" then
        -- Parse timestamp union with enhanced formatting
        if active_field.name == "secondsPastEpoch" and offset + 7 < buf:len() then
            local seconds = isbe and buf(offset, 8):int64() or buf(offset, 8):le_int64()
            local seconds_num = tonumber(tostring(seconds))
            local formatted_time = formatEpicsTimestamp(seconds_num, 0)
            tree:add(buf(offset, 8), string.format("secondsPastEpoch: %s (%s)", tostring(seconds), formatted_time))
            return offset + 8
        elseif active_field.name == "nanoseconds" and offset + 3 < buf:len() then
            local nanos = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
            tree:add(buf(offset, 4), string.format("nanoseconds: %d (%.3f ms)", nanos, nanos / 1000000.0))
            return offset + 4
        end
    end

    -- Default parsing for other union types
    if active_field then
        offset = parseValue(buf, offset, active_field.type, isbe, tree, active_field.name)
    end

    return offset
end

-- Phase 4: Enhanced NT type detection and formatting
local function detectNTType(nt_name)
    if not nt_name then return "Unknown", {} end

    local nt_types = {
        ["epics:nt/NTScalar:1.0"] = {
            name = "NTScalar",
            description = "Scalar value with optional alarm and timestamp",
            fields = {"value", "alarm", "timeStamp"}
        },
        ["epics:nt/NTTable:1.0"] = {
            name = "NTTable",
            description = "Table of columns with labels",
            fields = {"labels", "value", "alarm", "timeStamp"}
        },
        ["epics:nt/NTImage:1.0"] = {
            name = "NTImage",
            description = "2D image data with attributes",
            fields = {"value", "dimension", "attribute", "alarm", "timeStamp"}
        },
        ["epics:nt/NTEnum:1.0"] = {
            name = "NTEnum",
            description = "Enumerated value with choices",
            fields = {"value", "choices", "alarm", "timeStamp"}
        },
        ["epics:nt/NTMatrix:1.0"] = {
            name = "NTMatrix",
            description = "N-dimensional matrix data",
            fields = {"value", "dimension", "alarm", "timeStamp"}
        }
    }

    local nt_info = nt_types[nt_name]
    if nt_info then
        return nt_info.name, nt_info
    else
        return "Custom NT", {name = "Custom", description = "User-defined normative type", fields = {}}
    end
end

-- Structure to store field information during introspection parsing
local FieldInfo = {}
function FieldInfo:new(name, field_type)
    local obj = {name = name, type = field_type, fields = {}}
    setmetatable(obj, self)
    self.__index = self
    return obj
end

-- Enhanced field parser that stores field information
local function parseFieldInfo(buf, offset, isbe, depth)
    if not buf or offset >= buf:len() or depth > 10 then
        return offset, nil
    end

    local field_type = buf(offset, 1):uint()
    offset = offset + 1

    local field_info = FieldInfo:new("", field_type)

    if field_type == TYPE_CODE_STRUCT then -- struct
        local field_count, new_offset = readPVASize(buf, offset, isbe)
        offset = new_offset

        -- Parse nested fields
        for i = 1, math.min(field_count, 20) do
            if offset >= buf:len() then break end

            local field_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
            offset = name_offset

            local nested_offset, nested_field = parseFieldInfo(buf, offset, isbe, depth + 1)
            if nested_field then
                nested_field.name = field_name
                table.insert(field_info.fields, nested_field)
            end
            offset = nested_offset
        end

    elseif field_type == TYPE_CODE_UNION then -- union
        -- Skip union name
        local union_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
        offset = name_offset

        local field_count, new_offset = readPVASize(buf, offset, isbe)
        offset = new_offset

        -- Parse union choices
        for i = 1, math.min(field_count, 20) do
            if offset >= buf:len() then break end

            local choice_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
            offset = name_offset

            local choice_offset, choice_field = parseFieldInfo(buf, offset, isbe, depth + 1)
            if choice_field then
                choice_field.name = choice_name
                table.insert(field_info.fields, choice_field)
            end
            offset = choice_offset
        end
        
    elseif field_type == CACHE_STORE_CODE then -- cache store: 0xFD key FieldDesc
        if offset + 1 < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            field_info.cache_key = cache_key
            offset = offset + 2
            
            -- Parse the following FieldDesc tree
            if offset < buf:len() then
                local nested_offset, nested_field = parseFieldInfo(buf, offset, isbe, depth + 1)
                if nested_field then
                    field_info.cached_field = nested_field
                end
                offset = nested_offset
            end
        end
        
    elseif field_type == CACHE_FETCH_CODE then -- cache fetch: 0xFE key
        if offset + 1 < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            field_info.cache_key = cache_key
            offset = offset + 2
        end
    end

    return offset, field_info
end



-- Helper function to get type size (simplified version)
local function getTypeSize(type_byte)
    if type_byte == TYPE_CODE_BOOLEAN then return 1 -- bool
    elseif type_byte == TYPE_CODE_BYTE then return 1 -- int8_t
    elseif type_byte == TYPE_CODE_SHORT then return 2 -- int16_t
    elseif type_byte == TYPE_CODE_INT then return 4 -- int32_t
    elseif type_byte == TYPE_CODE_LONG then return 8 -- int64_t
    elseif type_byte == TYPE_CODE_UBYTE then return 1 -- uint8_t
    elseif type_byte == TYPE_CODE_USHORT then return 2 -- uint16_t
    elseif type_byte == TYPE_CODE_UINT then return 4 -- uint32_t
    elseif type_byte == TYPE_CODE_ULONG then return 8 -- uint64_t
    elseif type_byte == TYPE_CODE_FLOAT then return 4 -- float
    elseif type_byte == TYPE_CODE_DOUBLE then return 8 -- double
    else return 0 -- variable length or unknown
    end
end

-- Helper function to identify authentication method strings
-- Context-aware: "anonymous" is usually a username, not a method
local function isAuthMethod(str, position, prev_was_method)
    local s = str:string():lower()

    -- Strong method indicators
    local strong_methods = {"x509", "ca", "plain", "kerberos", "tls", "ssl", "digest", "basic"}
    for _, method in ipairs(strong_methods) do
        if s == method then
            return true
        end
    end

    -- "anonymous" is typically a username unless it's clearly in method position
    if s == "anonymous" then
        -- Treat as method only if we've already seen a method (meaning this starts a new entry)
        return prev_was_method
    end

    return false
end


-- Since PVA has some identifiable header we can
-- avoid having to select "Decode as..." every time :)
local function test_pva (buf, pkt, root)
  -- check for 8 byte minimum length, prefix [0xca, 1, _, cmd] where cmd is a valid command #
  if buf:len()<8 or buf(0,1):uint()~=0xca or buf(1,1):uint()==0 or not bcommands[buf(3,1):uint()]
  then
      return false
  end
  pva.dissector(buf, pkt, root)
  pkt.conversation = pva
  return true
end

local status, err = pcall(function() pva:register_heuristic("tcp", test_pva) end)
if not status then
  print("Failed to register PVA heuristic TCP dissector.  Must manually specify TCP port! (try newer wireshark?)")
  print(err)
end
-- Wireshark 2.0 errors if the same protocol name is given for two
-- heuristic dissectors, even for different transports.
local status, err = pcall(function() pva:register_heuristic("udp", test_pva) end)
if not status then
  print("Failed to register PVA heuristic UDP dissector.  Must manually specify UDP port! (try newer wireshark?)")
  print(err)
end

local function decodeStatus (buf, pkt, t, isbe)
  local code = buf(0,1):uint()
  local subt = t:add(fstatus, buf(0,1))
  if buf:len()>1 then
    buf = buf(1):tvb()
  end
  if code==0xff
  then
    return buf
  else
    local message, stack
    message, buf = decodeString(buf, isbe)
    stack, buf = decodeString(buf, isbe)
    subt:append_text(message:string())
    if(code~=0 and stack:len()>0)
    then
      subt:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
    end
    return buf
  end
end

local function pva_client_search (buf, pkt, t, isbe, cmd)
    local seq, port
    if isbe then
        seq = buf(0,4):uint()
        port = buf(24,2):uint()
    else
        seq = buf(0,4):le_uint()
        port = buf(24,2):le_uint()
    end
    pkt.cols.info:append("SEARCH("..seq)

    t:add(fsearch_seq, buf(0,4), seq)
    local mask = t:add(fsearch_mask, buf(4,1))
    mask:add(fsearch_mask_repl, buf(4,1))
    mask:add(fsearch_mask_bcast, buf(4,1))
    t:add(fsearch_addr, buf(8,16))
    t:add(fsearch_port, buf(24,2), port)

    local nproto, npv

    nproto, buf = decodeSize(buf(26), isbe)
    for i=0,nproto-1 do
        local name
        name, buf = decodeString(buf, isbe)
        t:add(fsearch_proto, name)
    end

    if isbe then
        npv = buf(0,2):uint()
    else
        npv = buf(0,2):le_uint()
    end
    t:add(fsearch_count, buf(0,2), npv);
    if npv>0 then
        buf = buf(2)

        for i=0,npv-1 do
            local cid, name
            if isbe then
                cid = buf(0,4):uint()
            else
                cid = buf(0,4):le_uint()
            end
            t:add(fsearch_cid, buf(0,4), cid)
            name, buf = decodeString(buf(4), isbe)
            t:add(fsearch_name, name)

            pkt.cols.info:append(', '..cid..":'"..name:string().."'")
        end
    end
    pkt.cols.info:append("), ")
end

local function pva_server_beacon (buf, pkt, t, isbe, cmd)
    local seq, change, port, proto

    t:add(fguid, buf(0,12))
    if isbe then
        seq = buf(13,1):uint()
        change = buf(14,2):uint()
        port = buf(32,2):uint()
    else
        seq = buf(13,1):le_uint()
        change = buf(14,2):le_uint()
        port = buf(32,2):le_uint()
    end
    t:add(fbeacon_seq, buf(13,1), seq)
    t:add(fbeacon_change, buf(14,2), change)
    t:add(fsearch_addr, buf(16,16))
    t:add(fsearch_port, buf(32,2), port)

    pkt.cols.info:append("BEACON(0x"..buf(0,12)..", "..seq..", "..change..")")

    proto, buf = decodeString(buf(34), isbe)
    t:add(fsearch_proto, proto)
end

local function pva_server_search_response (buf, pkt, t, isbe, cmd)
    local seq, port
    if isbe then
        seq = buf(12,4):uint()
        port = buf(32,2):uint()
    else
        seq = buf(12,4):le_uint()
        port = buf(32,2):le_uint()
    end
    pkt.cols.info:append("SEARCH_RESPONSE("..seq)

    t:add(fguid, buf(0,12))
    t:add(fsearch_seq, buf(12,4), seq)
    t:add(fsearch_addr, buf(16,16))
    t:add(fsearch_port, buf(32,2), port)

    local proto
    proto, buf = decodeString(buf(34), isbe)
    t:add(fsearch_proto, proto)

    t:add(fsearch_found, buf(0, 1))

    local npv
    if isbe then
        npv = buf(1,2):uint()
    else
        npv = buf(1,2):le_uint()
    end
    if npv>0 then
        buf = buf(3)

        for i=0,npv-1 do
            local cid, name

            if isbe then
                cid = buf(i*4,4):uint()
            else
                cid = buf(i*4,4):le_uint()
            end
            t:add(fsearch_cid, buf(i*4,4), cid)

            pkt.cols.info:append(', '..cid)
        end
    end
    pkt.cols.info:append(")")

end

local function pva_client_validate (buf, pkt, t, isbe, cmd)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local bsize, isize, qos
    if isbe
    then
        bsize = buf(0,4):uint()
        isize = buf(4,2):uint()
        qos = buf(6,2):uint()
    else
        bsize = buf(0,4):le_uint()
        isize = buf(4,2):le_uint()
        qos = buf(6,2):le_uint()
    end
    t:add(fvalid_bsize, buf(0,4), bsize)
    t:add(fvalid_isize, buf(4,2), isize)
    t:add(fvalid_qos, buf(6,2), qos)

    method, buf = decodeString(buf(8), isbe)

    -- Declare variables for authz processing
    local authzsize = 0
    local has_authz_extensions = false

    -- extensions to the AUTHZ message
    if (buf:len() > 1)
    then
	local authzmessage, authzflags
	authzmessage = buf(0,1):uint()
	if authzmessage == 0xfd
	then
	   buf=buf(3)
	end
	-- Add authz flags at the main level (applies to all entries)
	t:add(fvalid_azflg,  buf(1,1))
	authzflags = buf(1,1):uint()
    authzsize  = buf(2,1):uint()
	buf = buf(3)
	has_authz_extensions = true
    end

    -- Add appropriate info message based on method
    if method:string():lower() == "x509" then
        pkt.cols.info:append("X509 AUTHZ, ")
    elseif has_authz_extensions then
        if authzsize == 2 then
            pkt.cols.info:append("CA AUTHZ, ")
        elseif authzsize == 3 then
            pkt.cols.info:append("PVA AUTHZ, ")
        end
    end

    -- Start with basic auth entry for the method
    local entry_tree = t:add("AuthZ Entry 1")
    entry_tree:add(fvalid_method, method)

    -- Process authz extensions if present
    if has_authz_extensions and (buf and buf:len() > 0)
    then

	local peer, method_var, authority, account, isTLS
	if authzsize == 2
	then
	    buf = skipPVStructureLabelString(buf, isbe)
	    buf = skipPVStructureLabelString(buf, isbe)

	    account, buf = decodeString(buf, isbe)
	    peer, buf = decodeString(buf, isbe)

	    -- Add additional fields to the existing auth entry
	    entry_tree:add(fvalid_user, account)
	    entry_tree:add(fvalid_host, peer)

	elseif authzsize == 3
	then
	    buf = skipPVStructureLabelString(buf, isbe)
	    buf = skipPVStructureLabelString(buf, isbe)
	    buf = skipPVStructureLabelString(buf, isbe)

	    peer, buf = decodeString(buf, isbe)
	    authority, buf = decodeString(buf, isbe)
	    account, buf = decodeString(buf, isbe)

	    -- Add additional fields to the existing auth entry
	    entry_tree:add(fvalid_host, peer)
	    -- Only show AuthZ authority field when method is not 'ca'
	    if method:string():lower() ~= "ca" then
	        entry_tree:add(fvalid_authority, authority)
	    end
	    entry_tree:add(fvalid_user, account)
	    entry_tree:add(fvalid_isTLS, 1)
	end
    end
end

local function pva_server_validate (buf, pkt, t, isbe, cmd)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")

    if buf:len() >= 7 then
        -- Parse header: 4 bytes buffer size, 2 bytes introspection size, 1 byte flags
        local bsize, isize, flags
        if isbe
        then
            bsize = buf(0,4):uint()
            isize = buf(4,2):uint()
        else
            bsize = buf(0,4):le_uint()
            isize = buf(4,2):le_uint()
        end
        flags = buf(6,1):uint()

        t:add(fvalid_bsize, buf(0,4), bsize)
        t:add(fvalid_isize, buf(4,2), isize)
        t:add(fvalid_azflg, buf(6,1), flags)

        -- Parse all strings into a table first
        if buf:len() > 7 then
            local remaining = buf(7):tvb()
            local strings = {}

            -- Collect all strings
            while remaining and remaining:len() > 0 do
                local str
                str, remaining = decodeString(remaining, isbe)
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

                for i, str in ipairs(strings) do
                    if isAuthMethod(str, i, has_seen_method) then
                        -- This is a method string
                        if current_entry.method then
                            -- Current entry already has a method, start new entry
                            table.insert(auth_entries, current_entry)
                            current_entry = {method = str}
                        else
                            -- Add method to current entry
                            current_entry.method = str
                        end
                        has_seen_method = true
                    else
                        -- This is likely a name/user string
                        if not current_entry.name then
                            current_entry.name = str
                        else
                            -- Could be additional data like response
                            current_entry.response = str
                        end
                    end
                end

                -- Add the last entry
                if current_entry.method or current_entry.name or current_entry.response then
                    table.insert(auth_entries, current_entry)
                end

                -- Create subtrees for each auth entry
                for i, entry in ipairs(auth_entries) do
                    local entry_tree = t:add("AuthZ Entry " .. i)

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
                t:add(fbody, remaining)
            end
        end
    else
        -- Too short, show as raw body
        t:add(fbody, buf)
    end
end

local function pva_client_create_channel (buf, pkt, t, isbe, cmd)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local npv
    if isbe then
        npv = buf(0,2):uint()
    else
        npv = buf(0,2):le_uint()
    end
    buf = buf(2)

    for i=0,npv-1 do
        local cid, name
        if isbe then
            cid = buf(0,4):uint()
        else
            cid = buf(0,4):le_uint()
        end
        t:add(fsearch_cid, buf(0,4), cid)
        name, buf = decodeString(buf(4), isbe)
        t:add(fsearch_name, name)

        if i<npv-1 then pkt.cols.info:append("', '") end
        pkt.cols.info:append("'"..name:string())
    end
    pkt.cols.info:append("'), ")
end

local function pva_server_create_channel (buf, pkt, t, isbe, cmd)
    local cid, sid
    if isbe
    then
        cid = buf(0,4):uint()
        sid = buf(4,4):uint()
    else
        cid = buf(0,4):le_uint()
        sid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fcid, buf(0,4), cid)
    t:add(fsid, buf(4,4), sid)
    decodeStatus(buf(8), pkt, t, isbe)
end

local function pva_destroy_channel (buf, pkt, t, isbe, cmd)
    local cid, sid
    if isbe
    then
        sid = buf(0,4):uint()
        cid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        cid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fsid, buf(0,4), sid)
    t:add(fcid, buf(4,4), cid)
end

local function pva_client_op (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local sid, ioid, subcmd
    if isbe
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    subcmd = buf(8,1):uint()
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)
    local cmd = t:add(fsubcmd, buf(8,1), subcmd)
    cmd:add(fsubcmd_proc, buf(8,1), subcmd)
    cmd:add(fsubcmd_init, buf(8,1), subcmd)
    cmd:add(fsubcmd_dstr, buf(8,1), subcmd)
    cmd:add(fsubcmd_get, buf(8,1), subcmd)
    cmd:add(fsubcmd_gtpt, buf(8,1), subcmd)
    if buf:len()>9 then
        decodePVData(buf(9):tvb(), pkt, t, isbe, "PVData Body")
    end

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u, sub=%02x), ", cname, sid, ioid, subcmd))
end


local function pva_server_op (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local ioid, subcmd
    if isbe
    then
        ioid = buf(0,4):uint()
    else
        ioid = buf(0,4):le_uint()
    end
    subcmd = buf(4,1):uint()
    t:add(fioid, buf(0,4), ioid)
    local tcmd = t:add(fsubcmd, buf(4,1), subcmd)
    tcmd:add(fsubcmd_proc, buf(4,1), subcmd)
    tcmd:add(fsubcmd_init, buf(4,1), subcmd)
    tcmd:add(fsubcmd_dstr, buf(4,1), subcmd)
    tcmd:add(fsubcmd_get, buf(4,1), subcmd)
    tcmd:add(fsubcmd_gtpt, buf(4,1), subcmd)
    buf = buf(5):tvb()

    if cmd~=13 or bit.band(subcmd,0x08)~=0 then
        -- monitor updates have no status
        buf = decodeStatus(buf(0), pkt, t, isbe)
    end
    if buf and buf:len()>0 then
        decodePVData(buf, pkt, t, isbe, "PVData Body")
    end

    pkt.cols.info:append(string.format("%s(ioid=%u, sub=%02x), ", cname, ioid, subcmd))
end

local function pva_client_op_destroy (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local sid, ioid;
    if isbe
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u), ", cname, sid, ioid))
end

specials_server = {
    [0] = pva_server_beacon,
    [1] = pva_server_validate,
    [4] = pva_server_search_response,
    [7] = pva_server_create_channel,
    [8] = pva_destroy_channel,
    [10] = pva_server_op,
    [11] = pva_server_op,
    [12] = pva_server_op,
    [13] = pva_server_op,
    [14] = pva_server_op,
    [20] = pva_server_op,
}
specials_client = {
    [1] = pva_client_validate,
    [3] = pva_client_search,
    [7] = pva_client_create_channel,
    [8] = pva_destroy_channel,
    [10] = pva_client_op,
    [11] = pva_client_op,
    [12] = pva_client_op,
    [13] = pva_client_op,
    [14] = pva_client_op,
    [15] = pva_client_op_destroy,
    [20] = pva_client_op,
    [21] = pva_client_op_destroy,
}

-- PVData decoder function - Phase 3: Complete structure + value parsing
function decodePVData(buf, pkt, t, isbe, label)
    if not buf or buf:len() == 0 then
        return
    end

    -- Create main PVData tree (note: using buf only since fpvd ProtoField isn't in scope)
    local pvd_tree = t:add(placeholder, label or "PVData Body")

    if buf:len() == 0 then
        pvd_tree:append_text(" [Empty]")
        return pvd_tree
    end

    -- Parse first byte (type)
    local first_byte = buf(0, 1):uint()
    local type_name = PVD_TYPES[first_byte] or "unknown"
    
    -- Only show type info for non-cache types
    if first_byte ~= CACHE_STORE_CODE and first_byte ~= CACHE_FETCH_CODE then
        pvd_tree:append_text(string.format(" [Type: %s (0x%02X)]", type_name, first_byte))
    end

    local offset = 1
    local main_field_info = nil

    if first_byte == CACHE_STORE_CODE then -- cache store: 0xFD key FieldDesc
        if offset + 1 < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            pvd_tree:set_text(string.format("Cache Store %d", cache_key))
            offset = offset + 2
            
            -- Parse the following FieldDesc tree
            if offset < buf:len() then
                -- Parse the FieldDesc tree starting from current offset
                -- Check if the next byte is a structure type (0x80)
                if offset < buf:len() then
                    local struct_type = buf(offset, 1):uint()
                    if struct_type == TYPE_CODE_STRUCT then
                        offset = offset + 1 -- Skip the 0x80 type byte
                        
                        -- Read Type ID string
                        local type_id, type_id_offset = readPVString(buf, offset, isbe)
                        local nt_type = "struct"
                        if type_id and type_id ~= "" then
                            -- Use detectNTType to get clean name
                            local nt_name, nt_info = detectNTType(type_id)
                            if nt_name and nt_name ~= "Unknown" and nt_name ~= "Custom NT" then
                                nt_type = nt_name
                            else
                                                            -- For other types like alarm_t, enum_t, use the base name  
                            if type_id == "enum_t" then
                                nt_type = "enum_t"
                            else
                                nt_type = type_id:match("([^:]+)") or type_id
                            end
                            end
                        end
                        -- Update the cache store name to use field format
                        pvd_tree:set_text(string.format("value (0x%02X: %s)", TYPE_CODE_STRUCT, nt_type))
                        offset = type_id_offset
                        
                        -- Read field count
                        local field_count, count_offset = readPVSize(buf, offset, isbe)
                        -- pvd_tree:add(buf(offset, count_offset - offset), string.format("Field Count: %d", field_count))
                        offset = count_offset
                        
                        -- Parse each field (name + FieldDesc)
                        for i = 1, math.min(field_count, 20) do
                            if offset >= buf:len() then break end
                            
                            -- Read field name
                            local field_name, name_offset = readPVString(buf, offset, isbe)
                            offset = name_offset
                            
                            -- Parse field type recursively 
                            -- Check if the field is also a cache store
                            if offset < buf:len() then
                                local field_type = buf(offset, 1):uint()
                                if field_type == CACHE_STORE_CODE then
                                    -- Handle nested cache store
                                    offset = offset + 1  -- Skip 0xFD
                                                                         if offset + 1 < buf:len() then
                                         local nested_cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
                                         -- We'll update the cache_tree text after we know the type
                                         local cache_tree = pvd_tree:add(buf(offset - 1, 1), string.format("DEBUG: %s Cache %d (offset=%d, buflen=%d)", field_name or "field", nested_cache_key, offset, buf:len()))
                                         offset = offset + 2
                                        
                                        -- Parse the nested structure
                                        if offset < buf:len() then
                                            local next_type = buf(offset, 1):uint()
                                            -- Debug: add a temporary entry to show what type we detected
                                            if next_type == TYPE_CODE_STRUCT then
                                                offset = offset + 1  -- Skip 0x80
                                            
                                                                                         -- Read nested Type ID
                                             local nested_type_id, nested_type_offset = readPVString(buf, offset, isbe)
                                             local nested_nt_type = "struct"
                                             if nested_type_id and nested_type_id ~= "" then
                                                 -- Use detectNTType to get clean name
                                                 local nested_nt_name, nested_nt_info = detectNTType(nested_type_id)
                                                 if nested_nt_name and nested_nt_name ~= "Unknown" and nested_nt_name ~= "Custom NT" then
                                                     nested_nt_type = nested_nt_name
                                                 else
                                                                                      -- For other types like alarm_t, enum_t, use the base name
                                 if nested_type_id == "enum_t" then
                                     nested_nt_type = "enum_t"
                                 else
                                     nested_nt_type = nested_type_id:match("([^:]+)") or nested_type_id
                                 end
                                                 end
                                             end
                                             -- Update the nested cache store name to use field format with actual field name
                                             cache_tree:set_text(string.format("%s (0x%02X: %s)", field_name or "field", TYPE_CODE_STRUCT, nested_nt_type))
                                             offset = nested_type_offset
                                            
                                            -- Read nested field count
                                            local nested_field_count, nested_count_offset = readPVSize(buf, offset, isbe)
                                            -- cache_tree:add(buf(offset, nested_count_offset - offset), string.format("Field Count: %d", nested_field_count))
                                            offset = nested_count_offset
                                            
                                            -- Parse nested fields
                                            for j = 1, math.min(nested_field_count, 10) do
                                                if offset >= buf:len() then break end
                                                
                                                local nested_field_name, nested_name_offset = readPVString(buf, offset, isbe)
                                                offset = nested_name_offset
                                                
                                                -- Parse nested field type
                                                if offset < buf:len() then
                                                    local nested_field_type = buf(offset, 1):uint()
                                                    local nested_type_name = PVD_TYPES[nested_field_type] or string.format("unknown(0x%02X)", nested_field_type)
                                                    
                                                    -- Create field display in proper format
                                                    cache_tree:add(buf(offset, 1), string.format("%s (0x%02X: %s)", nested_field_name or "field", nested_field_type, nested_type_name))
                                                    offset = offset + 1
                                                    
                                                    -- Skip additional parsing for complex types - this is just FieldDesc structure
                                                end
                                            end
                                            else
                                                -- Not a struct, but some other type - just display it
                                                local other_type_name = PVD_TYPES[next_type] or string.format("unknown(0x%02X)", next_type)
                                                cache_tree:add(buf(offset, 1), string.format("field (0x%02X: %s)", next_type, other_type_name))
                                                offset = offset + 1
                                            end
                                        end
                                    end
                                    -- Cache store parsing complete - this counts as one field
                                    -- No additional parsing needed for this iteration
                                else
                                    -- Parse field type directly and create proper display
                                    local simple_field_type = buf(offset, 1):uint()
                                    local simple_type_name = PVD_TYPES[simple_field_type] or string.format("unknown(0x%02X)", simple_field_type)
                                    
                                    -- Create field display in proper format
                                    pvd_tree:add(buf(offset, 1), string.format("%s (0x%02X: %s)", field_name or "field", simple_field_type, simple_type_name))
                                    offset = offset + 1
                                    
                                    -- If cache store, consume the 2-byte cache key
                                    if simple_field_type == CACHE_STORE_CODE and offset + 1 < buf:len() then
                                        local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
                                        offset = offset + 2
                                    end
                                end
                            end
                        end
                    else
                        -- Not a structure, parse as regular FieldDesc
                        if offset < buf:len() then
                            local other_field_type = buf(offset, 1):uint()
                            local other_type_name = PVD_TYPES[other_field_type] or string.format("unknown(0x%02X)", other_field_type)
                            
                            -- Create field display in proper format
                            pvd_tree:add(buf(offset, 1), string.format("field (0x%02X: %s)", other_field_type, other_type_name))
                            offset = offset + 1
                            
                            -- If cache store, consume the 2-byte cache key
                            if other_field_type == CACHE_STORE_CODE and offset + 1 < buf:len() then
                                local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
                                pvd_tree:add(buf(offset, 2), string.format("DEBUG: Other path consuming cache key %d", cache_key))
                                offset = offset + 2
                            end
                        end
                    end
                end
                return pvd_tree
            end
        end
        
    elseif first_byte == CACHE_FETCH_CODE then -- cache fetch: 0xFE key
        if offset + 1 < buf:len() then
            -- Read 16-bit cache key
            local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
            pvd_tree:set_text(string.format("Cache Fetch %d", cache_key))
            return pvd_tree
        end

    elseif first_byte == TYPE_CODE_UNION then -- union
        -- Parse union name
        local union_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
        offset = name_offset

        if union_name ~= "" then
            -- Enhanced NT type detection and create clean tree
            local nt_type, nt_info = detectNTType(union_name)

            if nt_type ~= "Unknown" then
                -- Replace the main tree text with just the NT Type
                pvd_tree:set_text(string.format("NT Type: %s", nt_type))
            else
                pvd_tree:set_text(string.format("Union: %s", union_name))
            end
        else
            pvd_tree:set_text("Union")
        end

        -- Parse field count and fields
        if offset < buf:len() then
            local field_count, count_offset = readPVASize(buf, offset, isbe)
            offset = count_offset

            -- Parse fields with clean display
            for i = 1, math.min(field_count, 15) do
                if offset >= buf:len() then break end

                -- Read field name
                local field_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
                offset = name_offset

                -- Skip fields with empty names to avoid display issues
                if field_name == "" then
                    -- Read field type to advance offset properly
                    if offset < buf:len() then
                        local field_type = buf(offset, 1):uint()
                        offset = offset + 1

                        -- Skip any additional type-specific data
                        if field_type == TYPE_CODE_UNION then -- union - skip union name and field count
                            local union_name, union_name_offset = readPVAString(buf, offset, isbe, nil, nil)
                            offset = union_name_offset
                            if offset < buf:len() then
                                local union_field_count, union_count_offset = readPVASize(buf, offset, isbe)
                                offset = union_count_offset
                                -- Skip union choices - this would need more complex parsing
                            end
                        end
                    end
                else
                    -- Read field type and display cleanly
                    if offset < buf:len() then
                        local field_type = buf(offset, 1):uint()
                        local type_name = PVD_TYPES[field_type] or string.format("unknown(0x%02X)", field_type)
                        offset = offset + 1

                        if field_type == TYPE_CODE_UNION then -- union
                            -- Read union name
                            local union_name, union_name_offset = readPVAString(buf, offset, isbe, nil, nil)
                            offset = union_name_offset

                            -- Display with proper formatting for empty union names
                            local display_text
                            if union_name ~= "" then
                                display_text = string.format("%s: %s", union_name, field_name)
                            else
                                display_text = string.format("union: %s", field_name)
                            end
                            local union_tree = pvd_tree:add(buf(offset - union_name_offset, union_name_offset), display_text)

                            -- Read union field count
                            local union_field_count, union_count_offset = readPVASize(buf, offset, isbe)
                            offset = union_count_offset

                            -- Parse union choices
                            for j = 1, math.min(union_field_count, 20) do
                                if offset >= buf:len() then break end

                                local choice_name, choice_name_offset = readPVAString(buf, offset, isbe, nil, nil)
                                offset = choice_name_offset

                                if offset < buf:len() then
                                    local choice_type = buf(offset, 1):uint()
                                    local choice_type_name = PVD_TYPES[choice_type] or string.format("unknown(0x%02X)", choice_type)
                                    offset = offset + 1

                                    -- Display as "type (0xXX): name"
                                    union_tree:add(buf(offset - 1, 1), string.format("%s (0x%02X): %s", choice_type_name, choice_type, choice_name))
                                end
                            end

                        else
                            -- Simple type: display as "type (0xXX): name"
                            pvd_tree:add(buf(offset - 1, 1), string.format("%s (0x%02X): %s", type_name, field_type, field_name))
                            
                            -- If cache store, consume the 2-byte cache key
                            if field_type == CACHE_STORE_CODE and offset + 1 < buf:len() then
                                local cache_key = isbe and buf(offset, 2):uint() or buf(offset, 2):le_uint()
                                offset = offset + 2
                            end
                        end
                    end
                end
            end
        end

        -- Parse actual values if there are remaining bytes
        if offset < buf:len() then
            -- Read discriminator as simple byte (not size-encoded)
            local discriminator = buf(offset, 1):uint()
            offset = offset + 1

            if discriminator == 0 and offset < buf:len() then
                -- Choice 0 = "value" field 
                -- Check if it's a string or numeric type based on schema
                local str_len, str_offset = readPVASize(buf, offset, isbe)
                if str_offset + str_len <= buf:len() and str_len > 0 then
                    local str_val = buf(str_offset, str_len):string()
                    pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("value = \"%s\"", str_val))
                    offset = str_offset + str_len
                elseif offset + 3 < buf:len() then
                    -- Try as numeric
                    local int_val = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    pvd_tree:add(buf(offset, 4), string.format("value = %d", int_val))
                    offset = offset + 4
                end

            elseif discriminator == 1 and offset < buf:len() then
                -- Choice 1 = "alarm" union
                local alarm_disc = buf(offset, 1):uint()
                offset = offset + 1

                if alarm_disc == 0 and offset + 3 < buf:len() then
                    -- severity
                    local severity = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    pvd_tree:add(buf(offset, 4), string.format("alarm.severity = %d", severity))
                    offset = offset + 4
                elseif alarm_disc == 1 and offset + 3 < buf:len() then
                    -- status
                    local status = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    pvd_tree:add(buf(offset, 4), string.format("alarm.status = %d", status))
                    offset = offset + 4
                elseif alarm_disc == 2 and offset < buf:len() then
                    -- message string
                    local str_len, str_offset = readPVASize(buf, offset, isbe)
                    if str_offset + str_len <= buf:len() then
                        local str_val = str_len > 0 and buf(str_offset, str_len):string() or ""
                        pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("alarm.message = \"%s\"", str_val))
                        offset = str_offset + str_len
                    end
                end

            elseif discriminator == 2 and offset < buf:len() then
                -- Choice 2 = "timeStamp" field - parse actual timestamp data  
                if offset + 3 <= buf:len() then
                    -- Read 4-byte timestamp (EPICS seconds since 1990)
                    local epics_seconds = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    local formatted_time = formatEpicsTimestamp(epics_seconds, 0)
                    pvd_tree:add(buf(offset, 4), string.format("timeStamp = %d (%s)", epics_seconds, formatted_time))
                    offset = offset + 4
                    
                    -- Check for additional timestamp metadata/context
                    if offset < buf:len() then
                        local remaining_bytes = buf:len() - offset
                        if remaining_bytes > 0 then
                            -- Try to parse as string metadata
                            local str_len, str_offset = readPVASize(buf, offset, isbe)
                            if str_offset + str_len <= buf:len() and str_len > 0 and str_len < 50 then
                                local str_val = buf(str_offset, str_len):string()
                                pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("timeStamp.metadata = \"%s\"", str_val))
                                offset = str_offset + str_len
                            else
                                -- Show as raw data
                                pvd_tree:add(buf(offset, remaining_bytes), string.format("timeStamp.extra_data = %d bytes", remaining_bytes))
                                offset = buf:len()
                            end
                        end
                    end
                else
                    pvd_tree:add(buf(offset), string.format("timeStamp = [insufficient data, %d bytes]", buf:len() - offset))
                end
            end
        end

    elseif first_byte == TYPE_CODE_STRUCT then -- struct
        pvd_tree:set_text("Structure")

        -- Parse field count and fields
        if offset < buf:len() then
            local field_count, count_offset = readPVASize(buf, offset, isbe)
            offset = count_offset

            -- Parse fields with clean display
            for i = 1, math.min(field_count, 15) do
                if offset >= buf:len() then break end

                -- Read field name
                local field_name, name_offset = readPVAString(buf, offset, isbe, nil, nil)
                offset = name_offset

                -- Read field type and display cleanly
                if offset < buf:len() then
                    local field_type = buf(offset, 1):uint()
                    local type_name = PVD_TYPES[field_type] or string.format("unknown(0x%02X)", field_type)
                    offset = offset + 1

                    -- Simple type: display as "type (0xXX): name"
                    pvd_tree:add(buf(offset - 1, 1), string.format("%s (0x%02X): %s", type_name, field_type, field_name))
                end
            end
        end

        elseif first_byte == TYPE_CODE_INTROSPECTION_ONLY then -- introspectionOnly - values only
        pvd_tree:set_text("Values Only")

        -- DETAILED DEBUG: Show byte-by-byte parsing
        if offset < buf:len() then
            
            -- Show all remaining bytes
            local all_bytes = ""
            for i = 0, buf:len() - offset - 1 do
                all_bytes = all_bytes .. string.format("%02X ", buf(offset + i, 1):uint())
            end
            debug_tree:add(buf(offset), "All bytes: " .. all_bytes)
            
            -- Show discriminator as simple byte
            local discriminator = buf(offset, 1):uint()
            debug_tree:add(buf(offset, 1), string.format("Discriminator byte: %d (0x%02X)", discriminator, discriminator))
            
            -- Show next few bytes after discriminator
            if offset + 1 < buf:len() then
                local next_bytes = ""
                local bytes_to_show = math.min(8, buf:len() - offset - 1)
                for i = 0, bytes_to_show - 1 do
                    next_bytes = next_bytes .. string.format("%02X ", buf(offset + 1 + i, 1):uint())
                end
                if bytes_to_show > 0 then
                    debug_tree:add(buf(offset + 1, bytes_to_show), "Bytes after discriminator: " .. next_bytes)
                end
            end
        end

        -- Parse the value data with clean formatting
        if offset < buf:len() then
            -- Read discriminator as simple byte (not size-encoded)
            local discriminator = buf(offset, 1):uint()
            offset = offset + 1

            if discriminator == 0 and offset < buf:len() then
                -- Choice 0 = "value" field (string based on schema)
                local str_len, str_offset = readPVASize(buf, offset, isbe)
                if str_offset + str_len <= buf:len() then
                    local str_val = str_len > 0 and buf(str_offset, str_len):string() or ""
                    pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("value: \"%s\"", str_val))
                    offset = str_offset + str_len
                end

            elseif discriminator == 1 and offset < buf:len() then
                -- Choice 1 = "alarm" union
                local alarm_disc = buf(offset, 1):uint()
                offset = offset + 1

                if alarm_disc == 0 and offset + 3 < buf:len() then
                    -- severity
                    local severity = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    pvd_tree:add(buf(offset, 4), string.format("alarm.severity: %d", severity))
                    offset = offset + 4
                elseif alarm_disc == 1 and offset + 3 < buf:len() then
                    -- status
                    local status = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    pvd_tree:add(buf(offset, 4), string.format("alarm.status: %d", status))
                    offset = offset + 4
                elseif alarm_disc == 2 and offset < buf:len() then
                    -- message string
                    local str_len, str_offset = readPVASize(buf, offset, isbe)
                    if str_offset + str_len <= buf:len() then
                        local str_val = str_len > 0 and buf(str_offset, str_len):string() or ""
                        pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("alarm.message: \"%s\"", str_val))
                        offset = str_offset + str_len
                    end
                end

            elseif discriminator == 2 and offset < buf:len() then
                -- Choice 2 = "timeStamp" field - parse actual timestamp data
                if offset + 3 <= buf:len() then
                    -- Read 4-byte timestamp (EPICS seconds since 1990)
                    local epics_seconds = isbe and buf(offset, 4):int() or buf(offset, 4):le_int()
                    local formatted_time = formatEpicsTimestamp(epics_seconds, 0)
                    pvd_tree:add(buf(offset, 4), string.format("timeStamp: %d (%s)", epics_seconds, formatted_time))
                    offset = offset + 4
                    
                    -- Check for additional timestamp metadata/context
                    if offset < buf:len() then
                        local remaining_bytes = buf:len() - offset
                        if remaining_bytes > 0 then
                            -- Try to parse as string metadata
                            local str_len, str_offset = readPVASize(buf, offset, isbe)
                            if str_offset + str_len <= buf:len() and str_len > 0 and str_len < 50 then
                                local str_val = buf(str_offset, str_len):string()
                                pvd_tree:add(buf(offset, str_offset - offset + str_len), string.format("timeStamp.metadata: \"%s\"", str_val))
                                offset = str_offset + str_len
                            else
                                -- Show as raw data
                                pvd_tree:add(buf(offset, remaining_bytes), string.format("timeStamp.extra_data: %d bytes", remaining_bytes))
                                offset = buf:len()
                            end
                        end
                    end
                else
                    pvd_tree:add(buf(offset), string.format("timeStamp: [insufficient data, %d bytes]", buf:len() - offset))
                end

            else
                -- Unknown discriminator
                pvd_tree:add(buf(offset), string.format("Unknown discriminator %d - showing raw data", discriminator))
                pvd_tree:add(buf(offset), string.format("Raw data (%d bytes remaining)", buf:len() - offset))
            end
        end

    else
        -- Other types: show remaining data if any
        if buf:len() > offset then
            pvd_tree:add(buf(offset), string.format("Data (%d bytes)", buf:len() - offset))
        end
    end

    return pvd_tree
end

io.stderr:write("Loaded PVA\n")
