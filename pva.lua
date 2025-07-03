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
    fmagic, fver, fflags, fflag_dir, fflag_end, fflag_msgtype, fflag_segmented, fcmd, fctrlcmd, fctrldata, fsize, fbody, fpvd, fguid,
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

-- PVData type constants (Phase 2)
local PVD_TYPES = {
    [0x00] = "null",
    [0x01] = "introspectionOnly",
    [0x08] = "boolean", 
    [0x20] = "byte",
    [0x21] = "short", 
    [0x22] = "int",
    [0x23] = "long",
    [0x24] = "ubyte",
    [0x25] = "ushort",
    [0x26] = "uint", 
    [0x27] = "ulong",
    [0x2A] = "float",
    [0x2B] = "double",
    [0x40] = "byteArray",
    [0x41] = "shortArray", 
    [0x42] = "intArray",
    [0x43] = "longArray",
    [0x44] = "ubyteArray",
    [0x45] = "ushortArray",
    [0x46] = "uintArray",
    [0x47] = "ulongArray",
    [0x4A] = "floatArray",
    [0x4B] = "doubleArray",
    [0x50] = "boundedString",
    [0x60] = "string",
    [0x68] = "stringArray",
    [0x7F] = "structure",
    [0x80] = "union",
    [0x81] = "unionArray",
    [0x82] = "structureArray"
}

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
    if type_byte == 0x01 then -- introspectionOnly
        field_tree:append_text(" (introspection only - no data)")
        
    elseif type_byte == 0x7F then -- structure
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
        
    elseif type_byte == 0x80 then -- union
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
            end
        end
        
    elseif type_byte == 0x60 then -- string
        field_tree:append_text(" (string type)")
    elseif type_byte >= 0x20 and type_byte <= 0x2B then -- numeric types
        field_tree:append_text(string.format(" (%s type)", type_name))
    elseif type_byte == 0x08 then -- boolean
        field_tree:append_text(" (boolean type)")
    elseif type_byte >= 0x40 and type_byte <= 0x4B then -- array types
        field_tree:append_text(string.format(" (%s type)", type_name))
    elseif type_byte == 0x50 then -- boundedString
        field_tree:append_text(" (boundedString type)")
    elseif type_byte == 0x68 then -- stringArray
        field_tree:append_text(" (stringArray type)")
    elseif type_byte >= 0x81 and type_byte <= 0x82 then -- complex arrays
        field_tree:append_text(string.format(" (%s type)", type_name))
    else
        field_tree:append_text(string.format(" (unhandled type 0x%02X)", type_byte))
    end
    
    return offset
end

-- PVData decoder function - Phase 2: Structure parsing  
local function decodePVData(buf, pkt, t, isbe, label)
    if not buf or buf:len() == 0 then
        return
    end
    
    -- Create subtree for PVData
    local pvd_tree = t:add(fpvd_struct, buf, label or "PVData")
    
    -- Safe debug: just show first few bytes without string formatting
    if buf:len() > 0 then
        pvd_tree:add(fpvd_debug, buf(0, math.min(4, buf:len())), "First bytes (hex view)")
    end
    
    -- Simple parsing: just show first byte and remaining data
    if buf:len() > 0 then
        local first_byte = buf(0, 1):uint()
        local type_name = PVD_TYPES[first_byte] or "unknown"
        
        -- Show first byte without complex string formatting  
        local first_tree = pvd_tree:add(fpvd_introspection, buf(0, 1), "Type byte")
        first_tree:append_text(" = " .. type_name)
        
        -- Show remaining data
        if buf:len() > 1 then
            pvd_tree:add(fpvd_value, buf(1), "Data bytes")
        end
    end
    
    return pvd_tree
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

io.stderr:write("Loaded PVA\n")
