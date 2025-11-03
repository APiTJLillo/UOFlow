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
  { key = "helpers", label = "Helpers" },
  { key = "engine", label = "EngineCtx" },
  { key = "send", label = "SendBuilder" },
  { key = "fw", label = "FW Depth" },
  { key = "ack", label = "ACK ok/drop" },
  { key = "pace", label = "Pacing ms" },
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

  UOFlowStatus._rows = ROWS

  WindowSetShowing(list, true)

  local y = 0
  for i, row in ipairs(ROWS) do
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

local function safe_call(fn, ...)
  if type(fn) ~= "function" then
    debug_print("safe_call missing fn type=", type(fn))
    return nil
  end

  local ok, res = pcall(fn, ...)
  if ok then
    return res
  else
    debug_print("safe_call pcall failure:", tostring(res))
  end
  return nil
end

local STATUS_KEYS = {
  helpers = { key = "helpers", asBool = true },
  engineCtx = { key = "engine", asBool = true },
  sendReady = { key = "send", asBool = true },
  fwDepth = { key = "fw", asBool = false },
  stepDelayMs = { key = "pace", asBool = false },
  inflight = { key = "inflight", asBool = false },
}

local function coerce_value(value, asBool)
  if asBool then
    if type(value) == "boolean" then
      return value
    elseif type(value) == "number" then
      return value ~= 0
    end
  else
    if type(value) == "number" then
      return value
    elseif type(value) == "boolean" then
      return value and 1 or 0
    end
  end
  return nil
end

local function status_flags()
  local legacy = safe_call(UOW_StatusFlags)
  if type(legacy) == "table" then
    local outLegacy = {}
    outLegacy.helpers = coerce_value(legacy.helpers, true)
    outLegacy.engineCtx = coerce_value(legacy.engineCtx or legacy.engine, true)
    outLegacy.sendReady = coerce_value(legacy.sendReady or legacy.send, true)
    outLegacy.fwDepth = coerce_value(legacy.fwDepth or legacy.queueDepth or legacy.fw, false)
    outLegacy.stepDelayMs = coerce_value(legacy.stepDelayMs or legacy.stepDelay or legacy.pace, false)
    outLegacy.inflight = coerce_value(legacy.inflight, false)
    return outLegacy
  end

  local out = {}
  for field, cfg in pairs(STATUS_KEYS) do
    local raw = safe_call(UOW_StatusFlags, cfg.key)
    out[field] = coerce_value(raw, cfg.asBool)
  end
  return out
end

local function doPoll()
  local m = safe_call(GetWalkMetrics) or {}
  local flags = status_flags()
  debug_print(string.format(
    "UOFlowStatus.poll: helpers=%s engine=%s sendReady=%s fwDepth=%s acks=%s/%s stepDelay=%s inflight=%s",
    tostring(flags.helpers),
    tostring(flags.engineCtx),
    tostring(flags.sendReady),
    tostring(flags.fwDepth or m.queueDepth),
    tostring(m.acksOk or m.ack_ok or 0),
    tostring(m.acksDrop or m.ack_drop or 0),
    tostring(m.stepDelay or m.stepDelayMs or safe_call(GetPacing) or "n/a"),
    tostring(m.inflight or "n/a")
  ))

  do
    local base = W .. "ListRow1"
    local on = flags.helpers or false
    setDot(base .. "Dot", on and C.ok or C.bad)
    setText(base .. "Val", on and "installed" or "installing", on and C.ok or C.bad)
  end

  do
    local base = W .. "ListRow2"
    local on = flags.engineCtx or false
    local col = on and C.ok or C.warn
    setDot(base .. "Dot", col)
    setText(base .. "Val", on and "ready" or "waiting", col)
  end

  do
    local base = W .. "ListRow3"
    local on = flags.sendReady or false
    local col = on and C.ok or C.warn
    setDot(base .. "Dot", col)
    setText(base .. "Val", on and "ready" or "probing", col)
  end

  do
    local base = W .. "ListRow4"
    local d = flags.fwDepth or m.queueDepth or -1
    local good = (d or 0) > 0
    local col = good and C.ok or C.bad
    setDot(base .. "Dot", col)
    setText(base .. "Val", d >= 0 and tostring(d) or "n/a", col)
  end

  do
    local base = W .. "ListRow5"
    local okc = tonumber(m.acksOk or m.ack_ok or 0) or 0
    local drp = tonumber(m.acksDrop or m.ack_drop or 0) or 0
    local good = okc > 0 and drp == 0
    local col = good and C.ok or (drp > 0 and C.warn or C.dim)
    setDot(base .. "Dot", col)
    setText(base .. "Val", string.format("%d / %d", okc, drp), col)
  end

  do
    local base = W .. "ListRow6"
    local ms = tonumber(m.stepDelay or m.stepDelayMs or safe_call(GetPacing) or 0) or 0
    local infl = tonumber(m.inflight or 0) or 0
    local good = infl <= 1 and ms <= 400
    setDot(base .. "Dot", good and C.ok or C.warn)
    setText(base .. "Val", string.format("%d (inflight=%d)", ms, infl), C.text)
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



