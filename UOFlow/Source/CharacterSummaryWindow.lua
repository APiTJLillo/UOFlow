----------------------------------------------------------------
-- Character Summary Window
----------------------------------------------------------------

CharacterSummaryWindow = {}

CharacterSummaryWindow.MaxSkillIndex = 57
CharacterSummaryWindow.DisplayLabelCandidates = {
	"CharacterSummaryWindowScrollChildText",
	"CharacterSummaryWindowScrollScrollChildText",
	"CharacterSummaryWindowScrollChildTextLabel",
	"CharacterSummaryWindowScrollChildText_Label",
}
CharacterSummaryWindow.CopyBoxCandidates = {
	"CharacterSummaryWindowScrollChildCopyBox",
	"CharacterSummaryWindowScrollScrollChildCopyBox",
	"CharacterSummaryWindowScrollChildTextCopy",
}
CharacterSummaryWindow.ScrollChildCandidates = {
	"CharacterSummaryWindowScrollChild",
	"CharacterSummaryWindowScrollScrollChild",
	"CharacterSummaryWindowScrollChildWindow",
}
CharacterSummaryWindow.DisplayLabelName = CharacterSummaryWindow.DisplayLabelCandidates[1]
CharacterSummaryWindow.ScrollChildName = CharacterSummaryWindow.ScrollChildCandidates[1]
CharacterSummaryWindow.CopyBoxName = CharacterSummaryWindow.CopyBoxCandidates[1]
CharacterSummaryWindow.EditBoxName = CharacterSummaryWindow.CopyBoxName
CharacterSummaryWindow.DataRegistered = false
CharacterSummaryWindow.HasLoggedLabelMissing = false
CharacterSummaryWindow.HasLoggedCopyMissing = false
CharacterSummaryWindow.HasLoggedScrollMissing = false

CharacterSummaryWindow.EquipmentSlots =
{
	{ label = "Right Hand", id = EquipmentData.EQPOS_RIGHTHAND },
	{ label = "Left Hand", id = EquipmentData.EQPOS_LEFTHAND },
	{ label = "Head", id = EquipmentData.EQPOS_HEAD },
	{ label = "Neck", id = EquipmentData.EQPOS_NECK },
	{ label = "Earrings", id = EquipmentData.EQPOS_EARS },
	{ label = "Chest", id = EquipmentData.EQPOS_CHEST },
	{ label = "Arms", id = EquipmentData.EQPOS_ARMS },
	{ label = "Hands", id = EquipmentData.EQPOS_HANDS },
	{ label = "Legs", id = EquipmentData.EQPOS_LEGS },
	{ label = "Feet", id = EquipmentData.EQPOS_FEET },
	{ label = "Waist", id = EquipmentData.EQPOS_WAIST },
	{ label = "Talisman", id = EquipmentData.EQPOS_TALISMAN },
	{ label = "Ring", id = EquipmentData.EQPOS_FINGER1 },
	{ label = "Cape", id = EquipmentData.EQPOS_CAPE },
	{ label = "Backpack", id = EquipmentData.EQPOS_BACKPACK },
}

local function toPlainString(value)
	if value == nil then
		return ""
	end

	if type(value) == "string" then
		return value
	end

	local ok, result = pcall(WStringToString, value)
	if ok then
		return result
	end

	return tostring(value)
end

local function toWString(value)
	if value == nil then
		return L""
	end

	if type(value) == "wstring" then
		return value
	end

	local ok, result = pcall(StringToWString, tostring(value))
	if ok then
		return result
	end

	return L""
end

local function formatSkillValue(value)
	if value == nil then
		return "0.0"
	end

	return string.format("%.1f", tonumber(value) / 10)
end

local function setStatusMessage(message)
	LabelSetText("CharacterSummaryWindowStatus", toWString(message))
end

local dispatchDebugMessage

dispatchDebugMessage = function(message)
	if not message or message == "" then
		return false
	end

	local logged = false
	local wmessage = toWString(message)

	if Debug then
		if not logged and type(Debug.PrintToDebugConsole) == "function" then
			logged = pcall(Debug.PrintToDebugConsole, wmessage)
		end
		if not logged and type(Debug.Print) == "function" then
			logged = pcall(Debug.Print, wmessage)
		end
	end

	if not logged and Interface and type(Interface.AddToSystemJournal) == "function" then
		logged = pcall(Interface.AddToSystemJournal, wmessage)
	end

	if not logged and type(PrintWStringToChatWindow) == "function" and SystemData and SystemData.ChatLogFilters then
		logged = pcall(PrintWStringToChatWindow, wmessage, SystemData.ChatLogFilters.SYSTEM)
	end

	return logged
end

local function ensureEditBox()
	if DoesWindowNameExist(CharacterSummaryWindow.CopyBoxName) then
		return true
	end

	if not CharacterSummaryWindow.HasLoggedCopyMissing then
		CharacterSummaryWindow.HasLoggedCopyMissing = true
		dispatchDebugMessage("[CharacterSummary] Copy box not found: " .. CharacterSummaryWindow.CopyBoxName)
		if WindowList then
			dispatchDebugMessage("[CharacterSummary] Available windows containing 'CharacterSummary':")
			for name in pairs(WindowList) do
				if type(name) == "string" and string.find(name, "CharacterSummary", 1, true) then
					dispatchDebugMessage("  * " .. name)
				end
			end
		end
		for _, candidate in ipairs(CharacterSummaryWindow.CopyBoxCandidates) do
			if DoesWindowNameExist(candidate) then
				CharacterSummaryWindow.CopyBoxName = candidate
				CharacterSummaryWindow.EditBoxName = candidate
				dispatchDebugMessage("[CharacterSummary] Switched copy box to '" .. candidate .. "'.")
				return true
			end
		end
		dispatchDebugMessage("[CharacterSummary] Copy box candidates tried:")
		for _, candidate in ipairs(CharacterSummaryWindow.CopyBoxCandidates) do
			dispatchDebugMessage("  - " .. candidate)
		end
	end

	return false
end

local function ensureDisplayLabel()
	if DoesWindowNameExist(CharacterSummaryWindow.DisplayLabelName) then
		return true
	end

	if not CharacterSummaryWindow.HasLoggedLabelMissing then
		CharacterSummaryWindow.HasLoggedLabelMissing = true
		dispatchDebugMessage("[CharacterSummary] Display label not found: " .. CharacterSummaryWindow.DisplayLabelName)
		if WindowList then
			dispatchDebugMessage("[CharacterSummary] Available windows containing 'CharacterSummary':")
			for name in pairs(WindowList) do
				if type(name) == "string" and string.find(name, "CharacterSummary", 1, true) then
					dispatchDebugMessage("  * " .. name)
				end
			end
		end
		for _, candidate in ipairs(CharacterSummaryWindow.DisplayLabelCandidates) do
			if DoesWindowNameExist(candidate) then
				CharacterSummaryWindow.DisplayLabelName = candidate
				dispatchDebugMessage("[CharacterSummary] Switched display label to '" .. candidate .. "'.")
				return true
			end
		end
		dispatchDebugMessage("[CharacterSummary] Display label candidates tried:")
		for _, candidate in ipairs(CharacterSummaryWindow.DisplayLabelCandidates) do
			dispatchDebugMessage("  - " .. candidate)
		end
	end

	return false
end

local function ensureScrollChild()
	if DoesWindowNameExist(CharacterSummaryWindow.ScrollChildName) then
		return true
	end

	if not CharacterSummaryWindow.HasLoggedScrollMissing then
		CharacterSummaryWindow.HasLoggedScrollMissing = true
		dispatchDebugMessage("[CharacterSummary] Scroll child window not found: " .. CharacterSummaryWindow.ScrollChildName)
		if WindowList then
			dispatchDebugMessage("[CharacterSummary] Available windows containing 'CharacterSummary':")
			for name in pairs(WindowList) do
				if type(name) == "string" and string.find(name, "CharacterSummary", 1, true) then
					dispatchDebugMessage("  * " .. name)
				end
			end
		end
		for _, candidate in ipairs(CharacterSummaryWindow.ScrollChildCandidates) do
			if DoesWindowNameExist(candidate) then
				CharacterSummaryWindow.ScrollChildName = candidate
				dispatchDebugMessage("[CharacterSummary] Switched scroll child to '" .. candidate .. "'.")
				return true
			end
		end
		dispatchDebugMessage("[CharacterSummary] Scroll child candidates tried:")
		for _, candidate in ipairs(CharacterSummaryWindow.ScrollChildCandidates) do
			dispatchDebugMessage("  - " .. candidate)
		end
	end

	return false
end

local function logSummary(output)
	if not output or output == "" then
		dispatchDebugMessage("[CharacterSummary] No data available.")
		return
	end

	dispatchDebugMessage("[CharacterSummary] Dump follows:")

	for line in string.gmatch(output, "[^\n]+") do
		dispatchDebugMessage("  " .. line)
	end
end

function CharacterSummaryWindow.Initialize()
	WindowUtils.SetWindowTitle("CharacterSummaryWindow", L"Character Summary")
	ButtonSetText("CharacterSummaryWindowRefreshButton", L"Refresh")
	ButtonSetText("CharacterSummaryWindowCopyButton", L"Copy")
	CharacterSummaryWindow.HasLoggedLabelMissing = false
	CharacterSummaryWindow.HasLoggedCopyMissing = false
	CharacterSummaryWindow.HasLoggedScrollMissing = false
	CharacterSummaryWindow.RegisterData()

	if DoesWindowNameExist(CharacterSummaryWindow.CopyBoxName) then
		WindowSetDimensions(CharacterSummaryWindow.CopyBoxName, 1, 1)
		WindowSetAlpha(CharacterSummaryWindow.CopyBoxName, 0)
	end
end

function CharacterSummaryWindow.Shutdown()
	CharacterSummaryWindow.UnregisterData()
end

function CharacterSummaryWindow.OnShown()
	CharacterSummaryWindow.Refresh()
end

function CharacterSummaryWindow.RegisterData()
	if CharacterSummaryWindow.DataRegistered then
		return
	end

	RegisterWindowData(WindowData.PlayerStatus.Type, 0)
	RegisterWindowData(WindowData.SkillList.Type, 0)

	for i = 0, CharacterSummaryWindow.MaxSkillIndex do
		RegisterWindowData(WindowData.SkillDynamicData.Type, i)
	end

	for _, slot in ipairs(CharacterSummaryWindow.EquipmentSlots) do
		RegisterWindowData(WindowData.PlayerEquipmentSlot.Type, slot.id)
	end

	CharacterSummaryWindow.DataRegistered = true
end

function CharacterSummaryWindow.UnregisterData()
	if not CharacterSummaryWindow.DataRegistered then
		return
	end

	UnregisterWindowData(WindowData.PlayerStatus.Type, 0)
	UnregisterWindowData(WindowData.SkillList.Type, 0)

	for i = 0, CharacterSummaryWindow.MaxSkillIndex do
		UnregisterWindowData(WindowData.SkillDynamicData.Type, i)
	end

	for _, slot in ipairs(CharacterSummaryWindow.EquipmentSlots) do
		UnregisterWindowData(WindowData.PlayerEquipmentSlot.Type, slot.id)
	end

	CharacterSummaryWindow.DataRegistered = false
end

local function ensureSkillCSVLoaded()
	if not WindowData.SkillsCSV then
		UOBuildTableFromCSV("data/gamedata/skilldata.csv", "SkillsCSV")
	end
end

local function buildStatsSection()
	local status = WindowData.PlayerStatus
	if not status or status.PlayerId == 0 then
		return { "Stats", "  Data not available." }
	end

	local lines = { "Stats" }

	local function statPair(label, current, maximum)
		if maximum then
			table.insert(lines, string.format("  %s: %s/%s", label, tostring(current or 0), tostring(maximum or 0)))
		else
			table.insert(lines, string.format("  %s: %s", label, tostring(current or 0)))
		end
	end

	statPair("Hits", status.CurrentHealth, status.MaxHealth)
	statPair("Stamina", status.CurrentStamina, status.MaxStamina)
	statPair("Mana", status.CurrentMana, status.MaxMana)
	statPair("Strength", status.Strength)
	statPair("Dexterity", status.Dexterity)
	statPair("Intelligence", status.Intelligence)
	statPair("Stat Cap", status.StatCap)
	statPair("Luck", status.Luck)
	statPair("Weight", status.Weight, status.MaxWeight)
	statPair("Followers", status.Followers, status.MaxFollowers)

	table.insert(lines, "")
	table.insert(lines, "Resistances")
	local function resist(label, current, cap, altCap)
		local capVal = tonumber(cap or altCap or 0)
		if capVal > 0 then
			table.insert(lines, string.format("  %s: %s/%s", label, tostring(current or 0), tostring(capVal)))
		else
			table.insert(lines, string.format("  %s: %s", label, tostring(current or 0)))
		end
	end

	resist("Physical", status.PhysicalResist, status.PhysicalResistCap, status.PhysicalResistMax)
	resist("Fire", status.FireResist, status.FireResistCap, status.FireResistMax)
	resist("Cold", status.ColdResist, status.ColdResistCap, status.ColdResistMax)
	resist("Poison", status.PoisonResist, status.PoisonResistCap, status.PoisonResistMax)
	resist("Energy", status.EnergyResist, status.EnergyResistCap, status.EnergyResistMax)

	table.insert(lines, "")
	table.insert(lines, "Combat & Casting")
	statPair("Damage", status.MinDamage, status.MaxDamage)
	statPair("Hit Chance Increase", status.HitChanceIncrease)
	statPair("Defense Chance Increase", status.DefenseChanceIncrease)
	statPair("Swing Speed Increase", status.SwingSpeedIncrease)
	statPair("Damage Increase", status.DamageChanceIncrease)
	statPair("Lower Mana Cost", status.LowerManaCost)
	statPair("Lower Reagent Cost", status.LowerReagentCost)
	statPair("Spell Damage Increase", status.SpellDamageIncrease)
	statPair("Faster Casting", status.FasterCasting)
	statPair("Faster Cast Recovery", status.FasterCastRecovery)

	table.insert(lines, "")
	table.insert(lines, "Regeneration")
	statPair("Hit Point Regen", status.HitPointRegen)
	statPair("Stamina Regen", status.StamRegen)
	statPair("Mana Regen", status.ManaRegen)

	return lines
end

local function buildSkillsSection()
	ensureSkillCSVLoaded()

	if not WindowData.SkillsCSV or not WindowData.SkillDynamicData then
		return { "Skills", "  Data not available." }
	end

	local lines = { "Skills" }

	for i = 1, #WindowData.SkillsCSV do
		local entry = WindowData.SkillsCSV[i]
		if entry then
			local serverId = entry.ServerId
			local dynamic = WindowData.SkillDynamicData[serverId]

			if dynamic then
				local real = dynamic.RealSkillValue or 0
				local temp = dynamic.TempSkillValue or 0
				local cap = dynamic.SkillCap or 0

				if real > 0 or temp > 0 then
					local name = toPlainString(GetStringFromTid(entry.NameTid))
					local realStr = formatSkillValue(real)
					local capStr = formatSkillValue(cap)
					local tempStr = formatSkillValue(temp)

					if tempStr ~= realStr then
						table.insert(lines, string.format("  %s: %s/%s (mod %s)", name, realStr, capStr, tempStr))
					else
						table.insert(lines, string.format("  %s: %s/%s", name, realStr, capStr))
					end
				end
			end
		end
	end

	if #lines == 1 then
		table.insert(lines, "  No trained skills found.")
	end

	return lines
end

local function buildEquipmentSection()
	local lines = { "Equipment" }

	for _, slotInfo in ipairs(CharacterSummaryWindow.EquipmentSlots) do
		local slotData = WindowData.PlayerEquipmentSlot[slotInfo.id]

		if slotData and slotData.objectId and slotData.objectId ~= 0 then
			local props = ItemProperties.GetObjectProperties(slotData.objectId, nil, "Character Summary - equipment")

			if props and #props > 0 then
				local name = toPlainString(props[1])
				table.insert(lines, string.format("%s: %s", slotInfo.label, name))

				for index = 2, #props do
					local text = toPlainString(props[index])
					if text ~= "" then
						table.insert(lines, "  - " .. text)
					end
				end
			else
				table.insert(lines, string.format("%s: Item #%s", slotInfo.label, tostring(slotData.objectId)))
			end
		else
			table.insert(lines, string.format("%s: (empty)", slotInfo.label))
		end
	end

	return lines
end

function CharacterSummaryWindow.Refresh()
	CharacterSummaryWindow.RegisterData()

	local sections = {}

	local stats = buildStatsSection()
	if stats and #stats > 0 then
		table.insert(sections, table.concat(stats, "\n"))
	end

	local skills = buildSkillsSection()
	if skills and #skills > 0 then
		table.insert(sections, table.concat(skills, "\n"))
	end

	local equipment = buildEquipmentSection()
	if equipment and #equipment > 0 then
		table.insert(sections, table.concat(equipment, "\n"))
	end

	local output = table.concat(sections, "\n\n")
	local woutput = toWString(output)

	if ensureDisplayLabel() then
		LabelSetText(CharacterSummaryWindow.DisplayLabelName, woutput)

		local lineCount = 1
		if output ~= "" then
			local _, newlines = string.gsub(output, "\n", "")
			lineCount = newlines + 1
		end
		local height = math.max(40, lineCount * 18)
		WindowSetDimensions(CharacterSummaryWindow.DisplayLabelName, 410, height)

		if ensureScrollChild() then
			WindowSetDimensions(CharacterSummaryWindow.ScrollChildName, 410, height + 8)
		end
	end

	if ensureEditBox() then
		TextEditBoxSetText(CharacterSummaryWindow.EditBoxName, woutput)
	end

	if output == "" then
		setStatusMessage("No character data available.")
	else
		setStatusMessage("")
	end

	logSummary(output)
end

function CharacterSummaryWindow.RefreshButton()
	CharacterSummaryWindow.Refresh()
end

function CharacterSummaryWindow.CopyButton()
	if ensureEditBox() then
		local editBox = CharacterSummaryWindow.EditBoxName
		WindowAssignFocus(editBox, true)
		TextEditBoxSelectAll(editBox)
		setStatusMessage(L"Selection ready. Press Ctrl+C to copy.")
	end
end

