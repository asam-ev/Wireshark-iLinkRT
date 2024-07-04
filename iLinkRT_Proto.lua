-- iLinkRT_Proto.lua
-- Dissects telegrams defined by ASAM ILinkRT V3.0 specification


--    This program is free software; you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation; either version 2 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License along
--    with this program; if not, write to the Free Software Foundation, Inc.,
--    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


-- ASAM e.V.
-- Altlaufstr. 40
-- 85635 Höhenkirchen
-- Germany
-- info@asam.net


-- Usage
   -- copy this file to C:\Users\YourName\AppData\Roaming\Wireshark\plugins
   -- if the folder \plugins does not exist you must create it


-- ---- global definitions ----

iLinkRT_protocol = Proto("iLinkRT", "iLinkRT Protocol")
message_length   = ProtoField.uint16("iLinkRT.message_length", "Header - Message Length", base.DEC)
message_ctr      = ProtoField.uint16("iLinkRT.message_ctr", "Header - Message Counter", base.DEC)
message_cf1      = ProtoField.uint16("iLinkRT.message_cf1", "Header - Control Field", base.DEC)
message_fill     = ProtoField.uint16("iLinkRT.message_fill", "Header - Fill Bytes", base.DEC)
message_cf2      = ProtoField.uint16("iLinkRT.message_cf2", "Tail - Control Field", base.DEC)
command_id       = ProtoField.uint16("iLinkRT.command_id", "Command ID", base.HEX_DEC)
command_data     = ProtoField.none("iLinkRT.command_data", "Command Data", base.HEX)
event_id         = ProtoField.uint32("iLinkRT.event_id", "Event ID", base.HEX)
event_fill       = ProtoField.uint32("iLinkRT.event_fill", "Event FillByte", base.HEX)
event_timestamp  = ProtoField.uint64("iLinkRT.event_timestamp", "Event Timestamp", base.HEX)
event_data       = ProtoField.none("iLinkRT.event_data", "Event Data", base.UINT_BYTES)
daq_id           = ProtoField.uint32("iLinkRT.daq_id", "DAQ ID", base.HEX)
daq_fill         = ProtoField.uint32("iLinkRT.daq_fill", "DAQ FillByte", base.HEX)
daq_timestamp    = ProtoField.uint64("iLinkRT.daq_timestamp", "DAQ Timestamp", base.HEX)
daq_data         = ProtoField.none("iLinkRT.daq_data", "DAQ Data", base.UINT_BYTES)
data_A_UINT8     = ProtoField.uint16("iLinkRT.A_UINT8", "A_UINT8", base.HEX_DEC)
data_A_UINT16    = ProtoField.uint16("iLinkRT.A_UINT16", "A_UINT16", base.HEX_DEC)
data_A_UINT32    = ProtoField.uint32("iLinkRT.A_UINT32", "A_UINT32", base.HEX_DEC)
data_A_UINT64    = ProtoField.uint64("iLinkRT.A_UINT64", "A_UINT64", base.HEX_DEC)
data_A_DOUBLE    = ProtoField.double("iLinkRT.DOUBLE", "A_FLOAT64", base.DOUBLE)
data_STRING      = ProtoField.string("iLinkRT.STRING", "STRING", base.STRINGZ) -- without leading length info; with trailing 0

iLinkRT_protocol.fields = {message_length, message_ctr, message_cf1, message_fill, command_id, command_data, 
  event_id, event_fill, event_timestamp, event_data,
  daq_id, daq_fill, daq_timestamp, daq_data,
	data_A_UINT8, data_A_UINT16, data_A_UINT32, data_A_UINT64, data_A_DOUBLE, data_STRING, message_cf2 }



-- ---- heuristic_checker ----

local function iLinkRT_heuristic_checker(buffer, pinfo, tree)
  -- guard for length (ensure minimum length)
  length = buffer:len()
  if length < 10 then return false end

  -- guard for reserved bytes == 0 (to detect iLinkRT protocol)
  local reserved = buffer(6, 2):uint()
  if reserved > 0 then return false end

  -- assign dissector
	iLinkRT_protocol.dissector(buffer, pinfo, tree)
	return true
end


-- ---- dissector main function ----

function iLinkRT_protocol.dissector(buffer, pinfo, tree)
	local length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = iLinkRT_protocol.name
	local subtree = tree:add(iLinkRT_protocol, buffer(), "iLinkRT Protocol Data")
	subtree:add_le(message_length, buffer(0, 2))
	subtree:add_le(message_ctr, buffer(2, 2))
	subtree:add_le(message_cf1, buffer(4, 2))
	subtree:add_le(message_fill, buffer(6, 2))
	local cmd = buffer(8, 2):le_uint()
	local cmd2 = buffer(10, 2):le_uint()  -- in case of event or DAQ the DID is 4 byte 
	
	-- ---- ACK ----
	if cmd == 0x00FF then
		local cmd_name = "ACK"
		subtree:add_le(command_id, buffer(8, 2)):append_text(" (" .. cmd_name .. ")")
		if length > 12 then -- the ACK contains data
			subtree:add_le(command_data, buffer(10, length-12)):append_text(" (no detailed evaluation available)") 
		end
		subtree:add_le(message_cf2, buffer(length - 2, 2))
	
	-- ---- NAK ----
	elseif cmd == 0x00FE then
		local cmd_name = "NAK"
		subtree:add_le(command_id, buffer(8,2)):append_text(" (" .. cmd_name .. ")")
		subtree:add_le(data_A_UINT16, buffer(10, 2)):append_text(" (Standard Error Number)")
		subtree:add_le(data_A_UINT16, buffer(12, 2)):append_text(" (Vendor specific Error Number)")
		subtree:add_le(data_A_UINT16, buffer(14, 2)):append_text(" (Vendor specific Error Text Length)")
		local string_length = buffer(14, 2):le_uint()
		subtree:add_le(data_STRING, buffer(16, string_length)):append_text(" (Vendor specific Error Text)")
		subtree:add_le(message_cf2, buffer(length-2, 2))
	
	-- ---- Commands ----
	elseif ((cmd >= 0x0100) and (cmd < 0xFFFF)) or ((cmd == 0xFFFF) and (cmd2 < 0xFFFF)) then        -- differentiate between RT_GET_ALL_SERVER and EV_CLIENT_INFORMATION
		-- ---- Commands without data ----
		if length <= 12 then
			subtree:add_le(command_id, buffer(8, 2)):append_text(" (" .. get_cmd_name(cmd) .. ")")
			subtree:add_le(message_cf2, buffer(length - 2, 2))
		-- ---- Commands data ----
		else
			-- ---- generic command ID ----
			subtree:add_le(command_id, buffer(8, 2)):append_text(" (" .. get_cmd_name(cmd) .. ")")
			
			-- ---- specific command data ----
			local buffer_pos = 10 -- position behind command ID
			if cmd     == 0x0102 then data_RT_SERVER_CONNECT(subtree, buffer, buffer_pos)
			elseif cmd == 0x0200 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)
			elseif cmd == 0x0202 then data_RT_GET_CHARACTERISTIC_INFO(subtree, buffer, buffer_pos)
			elseif cmd == 0x0204 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)              -- same structure as RT_GET_DEVICE_INFO
			elseif cmd == 0x0205 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)              -- same structure as RT_GET_DEVICE_STATE
			elseif cmd == 0x0207 then data_RT_GET_MEASUREMENT_INFO(subtree, buffer, buffer_pos)
			elseif cmd == 0x0208 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)              -- same structure as RT_GET_RASTER_OVERVIEW
			elseif cmd == 0x0300 then data_RT_CHANGE_DESCRIPTION_FILE(subtree, buffer, buffer_pos)
			elseif cmd == 0x0301 then data_RT_CHANGE_DESCRIPTION_FILE(subtree, buffer, buffer_pos)       -- same structure as RT_CHANGE_HEX_FILE
			elseif cmd == 0x0302 then data_RT_CONFIGURE_SERVER(subtree, buffer, buffer_pos)
			elseif cmd == 0x0303 then data_RT_CHANGE_DESCRIPTION_FILE(subtree, buffer, buffer_pos)       -- same structure as RT_COPY_DATA_EXCHANGE_FILE_TO_DEVICE
			elseif cmd == 0x0304 then data_RT_DEVICE_CONNECT(subtree, buffer, buffer_pos)
			elseif cmd == 0x0305 then data_RT_DISTRIBUTE_EVENT(subtree, buffer, buffer_pos)
			elseif cmd == 0x0306 then data_RT_SAVE_HEX_FILE(subtree, buffer, buffer_pos) 
			elseif cmd == 0x0307 then data_RT_SELECT_CHARACTERISTIC_ID(subtree, buffer, buffer_pos)
			elseif cmd == 0x0308 then data_RT_SELECT_DEVICE(subtree, buffer, buffer_pos)
			elseif cmd == 0x0309 then data_RT_SELECT_DEVICE_SET(subtree, buffer, buffer_pos)
			elseif cmd == 0x030A then data_RT_SELECT_CHARACTERISTIC_ID(subtree, buffer, buffer_pos)      -- same structure as RT_SELECT_MEASUREMENT_ID
			elseif cmd == 0x0402 then data_RT_GET_DAQ_EVENT_INFO(subtree, buffer, buffer_pos)
			elseif cmd == 0x0403 then data_RT_GET_DAQ_EVENT_INFO(subtree, buffer, buffer_pos)            -- same structure as RT_GET_DAQ_MEASUREMENT_LIST
			elseif cmd == 0x0404 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)              -- same structure as RT_GET_DEVICE_DAQ_LIST
			elseif cmd == 0x0405 then data_RT_CONFIGURE_SERVER(subtree, buffer, buffer_pos)              -- same structure as RT_START_STOP_MEASURING
			elseif cmd == 0x0500 then data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)              -- same structure as RT_GET_CALPAGE
			elseif cmd == 0x0501 then data_RT_READ_CELL_VALUES(subtree, buffer, buffer_pos)
			elseif cmd == 0x0502 then data_RT_READ_CHARACTERISTIC(subtree, buffer, buffer_pos)
			elseif cmd == 0x0503 then data_RT_SET_CALPAGE(subtree, buffer, buffer_pos)
			elseif cmd == 0x0504 then data_RT_WRITE_CELL_VALUES(subtree, buffer, buffer_pos)
			elseif cmd == 0x0505 then data_RT_WRITE_CHARACTERISTIC(subtree, buffer, buffer_pos)
			elseif cmd == 0x0600 then data_RT_ADD_KEY_VALUE_PAIR_TO_RECORDER_FILE(subtree, buffer, buffer_pos)
			elseif cmd == 0x0601 then data_RT_CONFIGURE_RECORDER(subtree, buffer, buffer_pos)
			elseif cmd == 0x0602 then data_RT_CONTROL_RECORDER(subtree, buffer, buffer_pos)
			elseif cmd == 0x0604 then data_RT_GET_TRIGGER(subtree, buffer, buffer_pos)
			elseif cmd == 0x0605 then data_RT_SET_CLIENT_BOOKMARK(subtree, buffer, buffer_pos)
			elseif cmd == 0x0606 then data_RT_SET_RETRIGGERING(subtree, buffer, buffer_pos)
			elseif cmd == 0x0607 then data_RT_SET_TRIGGER(subtree, buffer, buffer_pos)
			elseif cmd == 0x0700 then data_RT_EXECUTE_SERVICE(subtree, buffer, buffer_pos)
			elseif cmd == 0x0701 then data_RT_GET_AVAILABLE_CHARACTERISTICS(subtree, buffer, buffer_pos)
			elseif cmd == 0x0702 then data_RT_GET_AVAILABLE_DEVICE_SETS(subtree, buffer, buffer_pos) 
			elseif cmd == 0x0703 then data_RT_GET_AVAILABLE_DEVICE_SETS(subtree, buffer, buffer_pos)     -- same structure as RT_GET_AVAILABLE_DEVICES
			elseif cmd == 0x0704 then data_RT_GET_AVAILABLE_CHARACTERISTICS(subtree, buffer, buffer_pos) -- same structure as RT_GET_AVAILABLE_MEASUREMENTS

			-- ---- generic command data ----
			else
				subtree:add_le(command_data, buffer(10, length-12))
			end

			-- ---- generic command tail ----
			subtree:add_le(message_cf2, buffer(length - 2, 2))
		end
		
	-- ---- DAQs ----
	elseif ((cmd < 0x00FE) and (cmd2 == 0x0000)) then
		local cmd_name = "DAQ"
		subtree:add_le(daq_id, buffer(8, 4))
		subtree:add_le(daq_fill, buffer(12, 4)):append_text(" (Fill Bytes)")
		subtree:add_le(daq_timestamp, buffer(16, 8))
		subtree:add_le(daq_data, buffer(24, length-26))
		subtree:add_le(message_cf2, buffer(length-2, 2))
	
	-- ---- Events ----
	elseif ((cmd < 0x00FE) and (cmd2 == 0x8000)) or ((cmd == 0xFFFF) and (cmd2 == 0xFFFF)) then      -- respect EV_CLIENT_INFORMATION
		local event = buffer(8, 4):le_uint()
		subtree:add_le(event_id, buffer(8, 4)):append_text(" (" .. get_event_name(event) .. ")")
		subtree:add_le(event_fill, buffer(12, 4))
		subtree:add_le(event_timestamp, buffer(16, 8))
		subtree:add_le(event_data, buffer(24, length - 26))
		subtree:add_le(message_cf2, buffer(length - 2, 2))
	
	end
end


-- ---- name handling ----

function get_cmd_name(cmd)
	local cmd_name = "Unknown"
	if cmd       == 0xFFFF then cmd_name = "RT_GET_ALL_SERVER"
		elseif cmd == 0x0100 then cmd_name = "RT_GET_SERVER_STATE"
		elseif cmd == 0x0101 then cmd_name = "RT_GET_SERVER_TIME"
		elseif cmd == 0x0102 then cmd_name = "RT_SERVER_CONNECT"
		elseif cmd == 0x0103 then cmd_name = "RT_SERVER_DISCONNECT"
		elseif cmd == 0x0200 then cmd_name = "RT_GET_CALPAGE_INFO"
		elseif cmd == 0x0201 then cmd_name = "RT_GET_CHARACTERISTIC_ID_LIST"
		elseif cmd == 0x0202 then cmd_name = "RT_GET_CHARACTERISTIC_INFO"
		elseif cmd == 0x0203 then cmd_name = "RT_GET_DAQ_RESOLUTION_INFO"
		elseif cmd == 0x0204 then cmd_name = "RT_GET_DEVICE_INFO"
		elseif cmd == 0x0205 then cmd_name = "RT_GET_DEVICE_STATE"
		elseif cmd == 0x0206 then cmd_name = "RT_GET_MEASUREMENT_ID_LIST"
		elseif cmd == 0x0207 then cmd_name = "RT_GET_MEASUREMENT_INFO"
		elseif cmd == 0x0208 then cmd_name = "RT_GET_RASTER_OVERVIEW"
		elseif cmd == 0x0209 then cmd_name = "RT_GET_SELECTED_DEVICES"
		elseif cmd == 0x0300 then cmd_name = "RT_CHANGE_DESCRIPTION_FILE"
		elseif cmd == 0x0301 then cmd_name = "RT_CHANGE_HEX_FILE"
		elseif cmd == 0x0302 then cmd_name = "RT_CONFIGURE_SERVER"
		elseif cmd == 0x0303 then cmd_name = "RT_COPY_DATA_EXCHANGE_FILE_TO_DEVICE"
		elseif cmd == 0x0304 then cmd_name = "RT_DEVICE_CONNECT"
		elseif cmd == 0x0305 then cmd_name = "RT_DISTRIBUTE_EVENT"
		elseif cmd == 0x0306 then cmd_name = "RT_SAVE_HEX_FILE"
		elseif cmd == 0x0307 then cmd_name = "RT_SELECT_CHARACTERISTIC_ID"
		elseif cmd == 0x0308 then cmd_name = "RT_SELECT_DEVICE"
		elseif cmd == 0x0309 then cmd_name = "RT_SELECT_DEVICE_SET"
		elseif cmd == 0x030A then cmd_name = "RT_SELECT_MEASUREMENT_ID"
		elseif cmd == 0x0400 then cmd_name = "RT_CLEAR_MEASURING_LIST"
		elseif cmd == 0x0401 then cmd_name = "RT_CONFIGURE_MEASURING"
		elseif cmd == 0x0402 then cmd_name = "RT_GET_DAQ_EVENT_INFO"
		elseif cmd == 0x0403 then cmd_name = "RT_GET_DAQ_MEASUREMENT_LIST"
		elseif cmd == 0x0404 then cmd_name = "RT_GET_DEVICE_DAQ_LIST"
		elseif cmd == 0x0405 then cmd_name = "RT_START_STOP_MEASURING"
		elseif cmd == 0x0500 then cmd_name = "RT_GET_CALPAGE"
		elseif cmd == 0x0501 then cmd_name = "RT_READ_CELL_VALUES"
		elseif cmd == 0x0502 then cmd_name = "RT_READ_CHARACTERISTIC"
		elseif cmd == 0x0503 then cmd_name = "RT_SET_CALPAGE"
		elseif cmd == 0x0504 then cmd_name = "RT_WRITE_CELL_VALUES"
		elseif cmd == 0x0505 then cmd_name = "RT_WRITE_CHARACTERISTIC"
		elseif cmd == 0x0600 then cmd_name = "RT_ADD_KEY_VALUE_PAIR_TO_RECORDER_FILE"
		elseif cmd == 0x0601 then cmd_name = "RT_CONFIGURE_RECORDER"
		elseif cmd == 0x0602 then cmd_name = "RT_CONTROL_RECORDER"
		elseif cmd == 0x0603 then cmd_name = "RT_GET_RETRIGGERING"
		elseif cmd == 0x0604 then cmd_name = "RT_GET_TRIGGER"
		elseif cmd == 0x0605 then cmd_name = "RT_SET_CLIENT_BOOKMARK"
		elseif cmd == 0x0606 then cmd_name = "RT_SET_RETRIGGERING"
		elseif cmd == 0x0607 then cmd_name = "RT_SET_TRIGGER"
		elseif cmd == 0x0700 then cmd_name = "RT_EXECUTE_SERVICE"
		elseif cmd == 0x0701 then cmd_name = "RT_GET_AVAILABLE_CHARACTERISTICS"
		elseif cmd == 0x0702 then cmd_name = "RT_GET_AVAILABLE_DEVICE_SETS"
		elseif cmd == 0x0703 then cmd_name = "RT_GET_AVAILABLE_DEVICES"
		elseif cmd == 0x0704 then cmd_name = "RT_GET_AVAILABLE_MEASUREMENTS"
	end
	return cmd_name
end

function get_event_name(event)
	local event_name = "Unknown"
	if event       == 0x80000000 then event_name = "Reserved"
		elseif event == 0x80000001 then event_name = "EV_DEVICE_CONFIGURATION_CHANGED"
		elseif event == 0x80000002 then event_name = "EV_DEVICE_CONNECTION"
		elseif event == 0x80000003 then event_name = "EV_ERROR"
		elseif event == 0x80000004 then event_name = "EV_MEASURING"
		elseif event == 0x80000005 then event_name = "EV_RECORDING"
		elseif event == 0x80000006 then event_name = "EV_SERVER"
		elseif event == 0xFFFFFFFF then event_name = "EV_CLIENT_INFORMATION"
	end
	return event_name
end


-- ---- special telegram evaluation ----

function data_RT_SERVER_CONNECT(subtree, buffer, buffer_pos)
	-- subtree: tree to add the info
	-- buffer: telegram data
	-- buffer_pos: position to start reading the buffer
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "MC-Client Name")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "MC-Client Vendor Name")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "MC-Client Product Name")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "MC-Client Product Version")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Requested UDPPort for unicast DAQ lists")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Reserved parameter")	
	return buffer_pos
end

function data_RT_GET_CALPAGE_INFO(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	return buffer_pos
end

function data_RT_GET_CHARACTERISTIC_INFO(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "CharacteristicId")	
	return buffer_pos
end

function data_RT_GET_MEASUREMENT_INFO(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "MeasurementId")	
	return buffer_pos
end

function data_RT_CHANGE_DESCRIPTION_FILE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileAbsolutePath")	
	return buffer_pos
end

function data_RT_CONFIGURE_SERVER(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "MODE")	
	return buffer_pos
end

function data_RT_DEVICE_CONNECT(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "CONNECTION_MODE")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "TRANSFER_MODE")	
	return buffer_pos
end

function data_RT_SELECT_CHARACTERISTIC_ID(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "Name")	
	return buffer_pos
end

function data_RT_DISTRIBUTE_EVENT(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "CLIENT_ACTIVITY")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "MC-Client message")	
	return buffer_pos
end

function data_RT_SAVE_HEX_FILE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileAbsolutePath")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "FORCE_OVERWRITE")	
	return buffer_pos
end

function data_RT_SELECT_DEVICE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "DeviceName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "DescriptionFileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "HexFileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "PhysicalLinkName")	
	return buffer_pos
end

function data_RT_SELECT_DEVICE_SET(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "DeviceSetName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "DeviceSetAbsolutePath")	
	return buffer_pos
end

function data_RT_GET_DAQ_EVENT_INFO(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DaqId")	
	return buffer_pos
end

function data_RT_READ_CELL_VALUES(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "CharacteristicId")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "REP_TYPE")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "X Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "X Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Y Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Y Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Z Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Z Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "W Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "W Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "V Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "V Axis position StopIndex")	
	return buffer_pos
end

function data_RT_READ_CHARACTERISTIC(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "CharacteristicId")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "REP_TYPE")	
	return buffer_pos
end

function data_RT_SET_CALPAGE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "PageIndex of page to set")	
	return buffer_pos
end

function data_RT_WRITE_CELL_VALUES(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "CharacteristicId")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "REP_TYPE")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "CHAR_VALUE_TYPE")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "X Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "X Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Y Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Y Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Z Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "Z Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "W Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "W Axis position StopIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "V Axis position StartIndex")	
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "V Axis position StopIndex")	
	local length = buffer:len()
	subtree:add_le(command_data, buffer(buffer_pos, length - buffer_pos - 2)):append_text(" (CellValues)")
	buffer_pos = length-12
	return buffer_pos
end

function data_RT_WRITE_CHARACTERISTIC(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "CharacteristicId")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "REP_TYPE")	
	local length = buffer:len()
	subtree:add_le(command_data, buffer(buffer_pos, length - buffer_pos - 2)):append_text(" (Axis- and Cell Values)")
	buffer_pos = length-12
	return buffer_pos
end

function data_RT_ADD_KEY_VALUE_PAIR_TO_RECORDER_FILE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "Path")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "Count (N) of Key Value Pairs")	
	-- limit the number of displayed key value pairs
	local count = buffer(buffer_pos - 1, 1):le_uint()
	local limited = false
	if count > 3 then
		count = 3
		limited = true
	end
	for i = 1,count do
		buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "key")	
		buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "value")	
	end
	if limited then
		local length = buffer:len()
		subtree:add_le(command_data, buffer(buffer_pos, length - buffer_pos - 2)):append_text(" (remaining key value pairs)")
	end
	return buffer_pos
end

function data_RT_CONFIGURE_RECORDER(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "FILE_DEVICE_COUNT")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "RETRIGGERING_FILE_CONTENT")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileAbsolutePath")	
	return buffer_pos
end

function data_RT_CONTROL_RECORDER(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "RECORDER_CONTROL")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "AUTO_MEASURING_CONTROL")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileName")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "FileAbsolutePath")	
	return buffer_pos
end

function data_RT_GET_TRIGGER(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "TRIGGER_KIND")	
end

function data_RT_SET_CLIENT_BOOKMARK(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT64(subtree, buffer, buffer_pos, "BookmarkIdentifier")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "BookmarkDescription")	
	return buffer_pos
end

function data_RT_SET_RETRIGGERING(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT64(subtree, buffer, buffer_pos, "RetriggerCount")	
	return buffer_pos
end

function data_RT_SET_TRIGGER(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "TRIGGER_KIND")	
	buffer_pos = data_RT_UINT08(subtree, buffer, buffer_pos, "TRIGGER_TYPE")	
	buffer_pos = data_RT_DOUBLE(subtree, buffer, buffer_pos, "DelayTime")	
	buffer_pos = data_RT_DOUBLE(subtree, buffer, buffer_pos, "TimeSpan")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "Condition")	
	return buffer_pos
end

function data_RT_EXECUTE_SERVICE(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "Service to be executed")	
	buffer_pos = data_RT_STRING(subtree, buffer, buffer_pos, "Service InputDataContainer")	
	return buffer_pos
end

function data_RT_GET_AVAILABLE_CHARACTERISTICS(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT16(subtree, buffer, buffer_pos, "DeviceId")	
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "StartPosition")	
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "RequiredNumber")	
	return buffer_pos
end

function data_RT_GET_AVAILABLE_DEVICE_SETS(subtree, buffer, buffer_pos)
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "StartPosition")	
	buffer_pos = data_RT_UINT32(subtree, buffer, buffer_pos, "RequiredNumber")	
	return buffer_pos
end


-- ---- dissect basic data ----

function data_RT_STRING(subtree, buffer, buffer_pos, string_description)
	-- buffer: telegram data
	-- buffer_pos: position to start reading the buffer
	-- string_description: explanation for the string
	subtree:add_le(data_A_UINT16, buffer(buffer_pos, 2)):append_text(" (String length incl. trailing 0)")
	local string_length = buffer(buffer_pos, 2):le_uint()
	buffer_pos = buffer_pos + 2
	subtree:add_le(data_STRING, buffer(buffer_pos, string_length)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + string_length
	return buffer_pos
end

function data_RT_UINT08(subtree, buffer, buffer_pos, string_description)
	subtree:add_le(data_A_UINT8, buffer(buffer_pos, 1)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + 1
	return buffer_pos
end

function data_RT_UINT16(subtree, buffer, buffer_pos, string_description)
	subtree:add_le(data_A_UINT16, buffer(buffer_pos, 2)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + 2
	return buffer_pos
end

function data_RT_UINT32(subtree, buffer, buffer_pos, string_description)
	subtree:add_le(data_A_UINT32, buffer(buffer_pos, 4)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + 4
	return buffer_pos
end

function data_RT_UINT64(subtree, buffer, buffer_pos, string_description)
	subtree:add_le(data_A_UINT64, buffer(buffer_pos, 8)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + 8
	return buffer_pos
end

function data_RT_DOUBLE(subtree, buffer, buffer_pos, string_description)
	subtree:add_le(data_A_DOUBLE, buffer(buffer_pos, 8)):append_text(" (" .. string_description .. ")")
	buffer_pos = buffer_pos + 8
	return buffer_pos
end



-- ---- dissector port assignment ----

local udp_port = DissectorTable.get("udp.port")
-- udp_port:add(8088, iLinkRT_protocol)
-- udp_port:add(8089, iLinkRT_protocol)
-- udp_port:add(8090, iLinkRT_protocol)
-- udp_port:add(8091, iLinkRT_protocol)
-- udp_port:add(8092, iLinkRT_protocol)
-- udp_port:add(8093, iLinkRT_protocol)



-- ---- dissector heuristic assignment, port independent ----

iLinkRT_protocol:register_heuristic("udp", iLinkRT_heuristic_checker)
