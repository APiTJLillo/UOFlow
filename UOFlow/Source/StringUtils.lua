
-- NOTE: This file is doccumented with NaturalDocs style comments. All comments begining with "--#' will
-- be included in the output.

------------------------------------------------------------------------------------------------------------------------------------------------
--# Title: String Utils
--#     This file contains string manipulation functions
------------------------------------------------------------------------------------------------------------------------------------------------

StringUtils = {}

----------------------------------------------------------------
-- String Manipulation Functions that are not defined in lua.
----------------------------------------------------------------

function StringSplit (inString, delimiter)
    local list = {}
    local pos = 1
  
    -- If delimiter is empty, use space as a default...
    if (delimiter == nil or delimiter == "") then 
       delimiter = " ";
    end
    
    while 1 do
        local first, last = string.find (inString, delimiter, pos, true);
    
        if first then -- found?
            table.insert (list, string.sub (inString, pos, first - 1));
            pos = last + 1;
        else
            table.insert (list, string.sub (inString, pos));
            break
        end
    end
  
    return list;
end

function string.split( str, separator )
	local result = {}
	local i = 0
	local idxs = string.find(str, separator)
	while idxs and idxs < string.len(str) do
		i = i + 1
		result[i] = string.sub(str, 1, idxs-1)
		str = string.sub(str, idxs+string.len(separator))
		idxs = string.find(str, separator)
		if not idxs then
			result[i+1] = str
		end
	end

	return result

end

function WStringSplit (inString, delimiter)
    local list = {}
    local pos = 1
  
    -- If delimiter is empty, use space as a default...
    if (delimiter == nil or delimiter == L"") then 
       delimiter = L" ";
    end
    
    while 1 do
        local first, last = wstring.find (inString, delimiter, pos, true);
    
        if first then -- found?
            table.insert (list, wstring.sub (inString, pos, first - 1));
            pos = last + 1;
        else
            table.insert (list, wstring.sub (inString, pos));
            break
        end
    end
  
    return list;
end

function StringsCompare( string1, string2 )

    if( string1 == nil ) then ERROR(L"Invalid params to StringsCompare( string1, string2 ): string1 is nil") end
    if( string2 == nil ) then ERROR(L"Invalid params to StringsCompare( string1, string2 ): string2 is nil") end


    -- Equals is built in
    if( string1 == string2 ) then
        return 0
    end
    
    -- Comparison is not.
    local len1 = string.len(string1)
    local len2 = string.len(string1)
    
    for index = 1, len1 do
        if( index > len2) then
            return 1
        end
            
        local char1 = string.byte( string1, index )
        local char2 = string.byte( string2, index )

        if( char1 < char2 ) then
            return -1
        elseif( char1 > char2 ) then
            return 1
        end     
    end
    
    return -1
end


function WStringsCompare( string1, string2 )

    if( string1 == nil ) then ERROR(L"Invalid params to WStringsCompare( string1, string2 ): string1 is nil") end
    if( string2 == nil ) then ERROR(L"Invalid params to WStringsCompare( string1, string2 ): string2 is nil") end

    -- There is now support in our Lua VM for wstring comparisons.
    if( string1 == string2 ) 
    then
        return 0
    elseif (string1 < string2)
    then
        return -1
    end

    return 1
end

local function tchelper(first, rest)
  return first:upper()..rest:lower()
end

function FormatProperly(wstring)
	if not wstring then
		return L""
	end
	if SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_ENU then
		return wstring
	end
	local str = string.lower(WStringToString(wstring))
	str = str:gsub("(%a)([%w_']*)", tchelper)
	return StringToWString(str)
end

function Knumber(number, decimal)
	if (number) then
		if (number >= 1000) then
			if decimal then
				local q = number / 100
				q = math.floor(q)
				number = q 
				if string.sub(number, -1) ~= "0" then
					number = string.sub(number, 1, -2) .. "." .. string.sub(number, -1)
				else
					q = math.floor(q/10)
					number = q 
				end
				number = StringToWString(number.."K")	
			else
				local q = number / 1000
				q = math.floor(q)
				number = StringToWString(tostring(q).."K")	
			end
		else
			number = StringToWString(tostring(number))	
		end
	end
	return number
end

----------------------------------------------------------------
-- String Util formating functions
----------------------------------------------------------------

function StringUtils.FormatNumberWString( number )
    
    -- Local variables
    local formatted_string  = L""
    local number_string     = L""..number
    
    local number_length     = wstring.len (number_string)
    local commas_needed     = math.ceil (number_length / 3) - 1
    
    if (commas_needed == 0) then
        formatted_string = number_string
        return formatted_string
    end
        
    local counter = 0   
    for i = number_length, 1, -3 do
        
        local sub_end       = (number_length) - (counter * 3)
        local sub_begin     = (sub_end - 2)
                
        local substring = wstring.sub (number_string, sub_begin, sub_end)
        formatted_string = L","..substring..formatted_string
                
        counter = counter + 1
        
        if (counter == commas_needed) then
            local remainder = wstring.sub (number_string, 0, sub_begin-1)
            formatted_string = remainder..formatted_string
            break;
        end
    end
        
    --DEBUG (formatted_string)
    
    return formatted_string
end

-- String Sorting Functions

StringUtils.SORT_ORDER_UP      = 1
StringUtils.SORT_ORDER_DOWN    = 2

function StringUtils.SortByString( string1, string2, order )     
    if( order == StringUtils.SORT_ORDER_UP ) then
        return (string1 < string2)
    else
        return (string1 > string2)
    end 
end

function wstring.trim(str)
	if not str then
		return
	end
	s1=str:find(L"[^%s]")
	if not s1 then return L"" end
	s2=str:find(L"%s*$") or 0
	return str:sub(s1,s2-1)
end

function string.trim(str)
	if not str then
		return
	end
	s1=str:find("[^%s]")
	if not s1 then return "" end
	s2=str:find("%s*$") or 0
	return str:sub(s1,s2-1)
end