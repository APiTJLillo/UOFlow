----------------------------------------------------------------
-- LuaUtils Global Variables
----------------------------------------------------------------    
LuaUtils = {}

----------------------------------------------------------------
-- LuaUtils Functions
----------------------------------------------------------------    
function LuaUtils.stripBeginEndSpace(inString)
	local inStringLen = wstring.len(inString)
	local beginIndex = 1
	local endIndex = inStringLen
	
	for i=1,inStringLen do
		if( wstring.sub(inString, i, i) ~= wstring.char(32) ) then
			beginIndex = i
			break
		end
	end
	
	for i=inStringLen,1,-1 do
		if( wstring.sub(inString, i, i) ~= wstring.char(32) ) then
			endIndex = i
			break
		end
	end
	
	local outString = wstring.sub(inString, beginIndex, endIndex)
	return outString
end

function LuaUtils.stripHTML(inString)
	local outString = L""
	local o1, o2, c1, c2
	c2 = 0
	o1, o2 = wstring.find(inString, L"<", 1, true)
	while o1 do
		if (c2+1 <= o1-1) then
			outString = outString..wstring.sub(inString, c2+1, o1-1)
		end
		c1, c2 = wstring.find(inString, L">", o1, true)
		o1, o2 = wstring.find(inString, L"<", c2, true)
	end
	if (c2+1 <= wstring.len(inString)) then
		outString = outString..wstring.sub(inString, c2+1, -1)
	end
	return (outString)
end

function table.copy(t)
	local t2 = {}
	for k,v in pairs(t) do
		t2[k] = v
	end
	return t2
end

function pairsByKeys (t, f)
	if not t then
		return
	end
    local a = {}
    for n in pairs(t) do
        table.insert(a, n)
    end
    table.sort(a, f)
    local i = 0      -- iterator variable
    local iter = function ()   -- iterator function
        i = i + 1
        if a[i] == nil then
                return nil
        else
                return a[i], t[a[i]]
        end
    end
    return iter
end

----------------------------------------------------------------
-- List 'class'
----------------------------------------------------------------    
    
function ListNew ()
    return {first = 0, last = -1}
end

List = {}
function List.new ()
    return {first = 0, last = -1}
end

function List.pushleft (list, value)
    local first = list.first - 1
    list.first = first
    list[first] = value
end

function List.pushright (list, value)
    local last = list.last + 1
    list.last = last
    list[last] = value
end

function List.popleft (list)
    local first = list.first
    if first > list.last then error("list is empty") end
    local value = list[first]
    list[first] = nil        -- to allow garbage collection
    list.first = first + 1
    return value
end

function List.popright (list)
    local last = list.last
    if list.first > last then error("list is empty") end
    local value = list[last]
    list[last] = nil         -- to allow garbage collection
    list.last = last - 1
    return value
end
