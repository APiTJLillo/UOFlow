-- UOFlowStatus.lua
UOFlowStatus = UOFlowStatus or {}

local W = "UOFlowStatusWindow"

local function color(r, g, b)
  return { r = r, g = g, b = b }
end

local C = {
  ok = color(0, 255, 0),
  warn = color(255, 192, 0),
  bad = color(255, 64, 64),
  dim = color(180, 180, 180),
  text = color(255, 255, 255),
}

local ROWS = {
  { key = "UOFlow.Walk.move", label = "Walk.move()" },
  { key = "nothing", label = "nothing" },
  { key = "nothing", label = "nothing" },
  { key = "nothing", label = "nothing" },
  { key = "nothing", label = "nothing" },
  { key = "nothing", label = "nothing" },
}

local BULLET = "+"

local poll -- forward declaration
local updateRegistered = false
local function debug_print(...)
  if type(Debug) ~= "table" or type(Debug.Print) ~= "function" then
    return
  end
  local pieces = {}
  for i = 1, select("#", ...) do
    local v = select(i, ...)
    pieces[#pieces + 1] = tostring(v)
  end
  local msg = table.concat(pieces)
  pcall(Debug.Print, towstring(msg))
end


local function setUpdateHandler(enabled)
  if enabled then
    if not updateRegistered then
      RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "UOFlowStatus.OnUpdate")
      updateRegistered = true
    end
  elseif updateRegistered then
    UnregisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "UOFlowStatus.OnUpdate")
    updateRegistered = false
  end
end

local function setText(id, s, col)
  if not DoesWindowExist(id) then
    return
  end

  if type(s) == "wstring" then
    LabelSetText(id, s)
  else
    LabelSetText(id, towstring(s or ""))
  end
  local c = col or C.text
  LabelSetTextColor(id, c.r, c.g, c.b)
end

-- Resolve dotted paths like "UOFlow.Walk.move" via _G
local function getByPath(path)
  if type(path) ~= "string" or path == "" then return nil end
  local cur = _G
  for seg in string.gmatch(path, "[^%.]+") do
    if type(cur) ~= "table" then return nil end
    cur = rawget(cur, seg)
    if cur == nil then return nil end
  end
  return cur
end

local function setDot(id, col)
  setText(id, BULLET, col or C.dim)
end

function UOFlowStatus.Build()
  local created = false
  if not DoesWindowExist(W) then
    CreateWindowFromTemplate(W, "UOFlowStatusWindowTemplate", "Root")
    if not DoesWindowExist(W) then
      if type(Debug) == "table" and type(Debug.Print) == "function" then
        pcall(Debug.Print, L"UOFlowStatus: failed to create window from template")
      end
      return
    end
    created = true
  end

  local list = W .. "List"
  if not DoesWindowExist(list) then
    if type(Debug) == "table" and type(Debug.Print) == "function" then
      pcall(Debug.Print, L"UOFlowStatus: list window missing")
    end
    return
  end

  -- Allow external code to override rows before Build()
  local rows = UOFlowStatus._rows or ROWS
  UOFlowStatus._rows = rows

  WindowSetShowing(list, true)

  local y = 0
  for i, row in ipairs(rows) do
    local base = list .. "Row" .. i
    if not DoesWindowExist(base) then
      CreateWindowFromTemplate(base, "UOFlowStatusRowTemplate", list)
    end
    WindowClearAnchors(base)
    WindowAddAnchor(base, "topleft", list, "topleft", 6, y)
    y = y + 18
    WindowSetShowing(base, true)
    setText(base .. "Label", row.label, C.text)
    setDot(base .. "Dot", C.dim)
    setText(base .. "Val", "", C.text)
  end

  if not WindowGetShowing(W) then
    WindowSetShowing(W, true)
  end

  poll()
  return true
end

local function safe_call(fn)
  if type(fn) ~= "function" then
    return nil
  end

  local ok, res = pcall(fn)
  if ok then
    return res
  end
  return nil
end

local function doPoll()
  -- Iterate all configured rows and show availability
  local rows = UOFlowStatus._rows or ROWS
  for i, row in ipairs(rows) do
    local base = W .. "ListRow" .. i
    if DoesWindowExist(base) then
      local key = type(row) == "table" and row.key or nil
      local ok = false
      if type(key) == "string" and key ~= "" then
        ok = getByPath(key) ~= nil
      end

      setDot(base .. "Dot", ok and C.ok or C.bad)
      setText(base .. "Val", ok and "installed" or "not installed", ok and C.ok or C.bad)
    end
  end

end

poll = doPoll

local accum = 0
local FRAME_FALLBACK = 0.016

function UOFlowStatus.OnUpdate(timePassed)
  if not DoesWindowExist(W) or not WindowGetShowing(W) then
    if updateRegistered then
      setUpdateHandler(false)
    end
    accum = 0
    return
  end

  local dt = timePassed
  if type(dt) ~= "number" or dt <= 0 then
    dt = FRAME_FALLBACK
  end

  accum = accum + dt
  if accum >= 0.25 then
    poll()
    accum = 0
  end
end

function UOFlowStatus.Initialize()
  if UOFlowStatus.Build() then
    setUpdateHandler(true)
    return true
  end
  return false
end

function UOFlowStatus.Show()
  if not DoesWindowExist(W) then
    if not UOFlowStatus.Initialize() then
      return
    end
  end

  if not DoesWindowExist(W .. "ListRow1") then
    if not UOFlowStatus.Build() then
      return
    end
  end

  if not WindowGetShowing(W) then
    WindowSetShowing(W, true)
  end

  setUpdateHandler(true)
  poll()
end

function UOFlowStatus.Hide()
  if not DoesWindowExist(W) then
    return
  end
  if WindowGetShowing(W) then
    WindowSetShowing(W, false)
  end
  setUpdateHandler(false)
end

function UOFlowStatus.Toggle()
  if not DoesWindowExist(W) then
    UOFlowStatus.Show()
    return
  end

  if WindowGetShowing(W) then
    UOFlowStatus.Hide()
  else
    UOFlowStatus.Show()
  end
end
