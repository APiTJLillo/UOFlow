----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

VendorSearch = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

VendorSearch.WindowName = "VendorSearch"
VendorSearch.HoldOn = false -- prevents the window closing when the gump reloads
VendorSearch.PriceSortSet = 0
VendorSearch.TotalCriteriaExpected = 21
VendorSearch.SearchGumpId = 999112
VendorSearch.NumberOfCatagories = 23 -- NumberOfCatagories == The number of elements in VendorSearch.CategoriesButtons + 1 
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function VendorSearch.Initialize()
	Interface.DestroyWindowOnClose[VendorSearch.WindowName] = true
	SnapUtils.SnappableWindows[VendorSearch.WindowName] = true
	WindowUtils.RestoreWindowPosition(VendorSearch.WindowName,true)
	WindowUtils.SetWindowTitle(VendorSearch.WindowName,GetStringFromTid(1154508))  -- Vendor Search Query
	WindowSetDimensions(VendorSearch.WindowName,  900,830)
	
	LabelSetText(VendorSearch.WindowName .. "ItemName", GetStringFromTid(1154510)) -- Item Name
	
	LabelSetText(VendorSearch.WindowName .. "PriceRange", GetStringFromTid(1155389))
	LabelSetText(VendorSearch.WindowName .. "PriceRangeSep", L"-")
	
	LabelSetText(VendorSearch.WindowName .. "MinPrice", GetStringFromTid(1154532)) -- Minimum Price
	LabelSetText(VendorSearch.WindowName .. "MaxPrice", GetStringFromTid(1154533)) -- Maximum Price
	
	LabelSetText(VendorSearch.WindowName .. "Misc", GetStringFromTid(1011173)) -- Miscellaneous
	LabelSetText(VendorSearch.WindowName .. "Equip", GetStringFromTid(1078237)) -- Equipment
	LabelSetText(VendorSearch.WindowName .. "Props", GetStringFromTid(1062761)) -- Properties
	LabelSetText(VendorSearch.WindowName .. "Combat", GetStringFromTid(1077417)) -- Combat
	LabelSetText(VendorSearch.WindowName .. "Casting", GetStringFromTid(1076209)) -- Casting
	LabelSetText(VendorSearch.WindowName .. "DamageType", GetStringFromTid(1154535)) -- Damage Type
	LabelSetText(VendorSearch.WindowName .. "Slayers", GetStringFromTid(1114263)) -- Slayers
	LabelSetText(VendorSearch.WindowName .. "Resist", GetStringFromTid(1114254)) -- Resists
	LabelSetText(VendorSearch.WindowName .. "Stats", GetStringFromTid(1114262)) -- Stats
	LabelSetText(VendorSearch.WindowName .. "Skills", GetStringFromTid(1115030)) -- Skills
	LabelSetText(VendorSearch.WindowName .. "HitSpell", GetStringFromTid(1154536)) -- Hit Spell
	LabelSetText(VendorSearch.WindowName .. "HitArea", GetStringFromTid(1154537)) -- Hit Area
	LabelSetText(VendorSearch.WindowName .. "SkillReq", GetStringFromTid(1154543)) -- Required Skill
	
	LabelSetText(VendorSearch.WindowName .. "ClearSearch", GetStringFromTid(1154588)) -- Clear Search Criteria
	LabelSetText(VendorSearch.WindowName .. "Search", GetStringFromTid(1154641)) -- Search
	
	LabelSetText(VendorSearch.WindowName .. "CriteriaMax", GetStringFromTid(1154681)) -- You may not add any more search criteria items.
	WindowSetShowing(VendorSearch.WindowName .. "CriteriaMax", false)
	
	LabelSetText(VendorSearch.WindowName .. "CriteriaText", GetStringFromTid(1154546)) -- Selected Search Criteria
	WindowUtils.DrawObjectIcon(3823, 0, VendorSearch.WindowName .. "GoldIcon")
	WindowUtils.DrawObjectIcon(39960, 0, VendorSearch.WindowName .. "ToggleAuctionIcon")	
	
	VendorSearch.UpdateButtonsMap()
	
	VendorSearch.SetLoading(false)
	
end

function VendorSearch.Shutdown()	
	VendorSearch.SetLoading(false)
	if GumpsParsing.ParsedGumps[VendorSearch.SearchGumpId] then
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.Cancel)
	end
	SnapUtils.SnappableWindows[VendorSearch.WindowName] = nil
	WindowUtils.SaveWindowPosition(VendorSearch.WindowName)
	WindowSetShowing(VendorSearch.WindowName,false)
end

function VendorSearch.CountCriteria()
	local count =  0
	local lastSearchPropFound = false
	if GumpsParsing.ParsedGumps[VendorSearch.SearchGumpId] then
		for label, data in pairs(GumpData.Gumps[VendorSearch.SearchGumpId].Labels) do
			if count > VendorSearch.TotalCriteriaExpected then				
				break
			end			
			if data.tid == 1159353 or data.tid == 1159354 then -- Auction Item || Non Auction Item
				lastSearchPropFound = true
				count = count + 1
				break
			elseif data.tid == 1154546 or data.tid == 1114513 then -- Ignore
				continue
			elseif data.tid == 1154510 and (count > 1 or lastSearchPropFound == false) and data.id > 3 then -- item name				
				break
			else
				count = count + 1
			end
		end
	end
	if not lastSearchPropFound then
		count = 0
	end	
	return count
end

function VendorSearch.GetError()
	if GumpsParsing.ParsedGumps[VendorSearch.SearchGumpId] then
		for label, data in pairs(GumpData.Gumps[VendorSearch.SearchGumpId].Labels) do
			if data.tid == 1150300 then
				if GumpData.Gumps[VendorSearch.SearchGumpId].Labels[label+1].tid ~= 1114514 then
					if GumpData.Gumps[VendorSearch.SearchGumpId].Labels[label+1].tid ~= 1154681 then
						return GumpData.Gumps[VendorSearch.SearchGumpId].Labels[label+1].tid
					else
						return
					end
				else
					return
				end
			end
		end
	end
end

VendorSearch.OldCriteriaLabels = 0

-- To be executed everytime a criteria is added
function VendorSearch.UpdateButtonsMap() 
	
	VendorSearch.TotalCriteria = VendorSearch.CountCriteria()	
	--------------------------------------------------------------------------------------------------
	--
	--	BUTTONS MAP
	--
	--------------------------------------------------------------------------------------------------
	-- Excluding the main buttons, most of the data must be put inside combo boxes.
	-- 
	-- NOTE: all the ButtonID must be sum to the number of criteria already in place
	--
	--------------------------------------------------------------------------------------------------
	--
	-- STRUCTURE EXAMPLE:
	-- [ComboBoxID] = {buttonID=XXX, buttonText="", tid=NNNNNN, [textboxId=YYY] };
	--
	-- If the textboxId is specified, the text box must be shown near the combobox.
	--------------------------------------------------------------------------------------------------
	
	VendorSearch.Cancel = VendorSearch.TotalCriteria + VendorSearch.NumberOfCatagories
	VendorSearch.Search = VendorSearch.TotalCriteria + VendorSearch.NumberOfCatagories+1
	VendorSearch.ClearSearch = VendorSearch.TotalCriteria + VendorSearch.NumberOfCatagories+2
	VendorSearch.ConfirmPriceRange = VendorSearch.TotalCriteria + VendorSearch.NumberOfCatagories+3
	
	local cost = VendorSearch.TotalCriteria + 4
	local minn = string.gsub(tostring(TextEditBoxGetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[2])), ",", "")
	minn = tonumber(minn)

	local maxx = string.gsub(tostring(TextEditBoxGetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[3])), ",", "")
	maxx = tonumber(maxx)

	VendorSearch.PriceRange = {
		min = minn,
		max = maxx
	}
	local error = VendorSearch.GetError()
	if error then
		LabelSetText(VendorSearch.WindowName .. "OtherError", GetStringFromTid(error))
		WindowSetAlpha(VendorSearch.WindowName .. "OtherError", 255)
		WindowStartAlphaAnimation(VendorSearch.WindowName .. "OtherError", Window.AnimationType.EASE_OUT, 1, 0, 1, false, 5, 0)
	else
		WindowSetAlpha(VendorSearch.WindowName .. "OtherError", 0)
	end
	
	TextEditBoxSetText(VendorSearch.WindowName .. "MinPriceText", towstring(VendorSearch.PriceRange.min))
	TextEditBoxSetText(VendorSearch.WindowName .. "MaxPriceText", towstring(VendorSearch.PriceRange.max))
		
	VendorSearch.PriceLowToHigh = true
	VendorSearch.IsAuctionSearch = false
	
	VendorSearch.CurrentCriteriaButtons = {}
	
	local dialog = "VendorSearchSW"
	local parent = dialog.. "ScrollChild"
	
	for i = 1, VendorSearch.OldCriteriaLabels do
		local slotName = parent.."Item"..i
		if DoesWindowNameExist(slotName) then
			DestroyWindow(slotName)
		end
	end
	WindowSetShowing(VendorSearch.WindowName .. "ItemNameButton", false)
	
	
	local i = 0
	for j = 0, VendorSearch.TotalCriteria + 1 do
		if GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1154546 or GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1114513 then
			continue
		end
		i = i + 1
		
		if GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1154696 then
			VendorSearch.PriceLowToHigh = true
			local button = VendorSearch.WindowName .. "LowHighButton"
			WindowSetDimensions(button, 22, 22)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL, "arrowdown", 0, 0)		
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED, "arrowdown", 0, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "arrowdown", 24 , 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "arrowdown", 24 , 0)
			VendorSearch.PriceSortSet = 1
			continue
		elseif GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1154697 then
			VendorSearch.PriceLowToHigh = false
			local button = VendorSearch.WindowName .. "LowHighButton"
			WindowSetDimensions(button, 22, 22)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL, "arrowup", 0, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED, "arrowup", 0, 0)		
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "arrowup", 24, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "arrowup", 24, 0)
			VendorSearch.PriceSortSet = 1
			continue
		end

		if GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1159353 then -- Auction Item	
			VendorSearch.IsAuctionSearch = true
			local button = VendorSearch.WindowName .. "ToggleAuctionButton"
			WindowSetDimensions(button, 16, 16)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL, "CheckBox", 18, 0)		
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED, "CheckBox", 18, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "CheckBox", 18 , 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "CheckBox", 0 , 0)			
			continue
		elseif GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1159354 then
			VendorSearch.IsAuctionSearch = false
			local button = VendorSearch.WindowName .. "ToggleAuctionButton"
			WindowSetDimensions(button, 16, 16)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL, "CheckBox", 0, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED, "CheckBox", 0, 0)		
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "CheckBox", 0, 0)
			ButtonSetTexture(button, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "CheckBox", 18, 0)			
			continue
		end

		local itemName
		local textParam
		if  GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid == 1154510 then
			local name =  wstring.trim(TextEditBoxGetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[1]))
			textParam = L": " ..name
			itemName = name
			TextEditBoxSetText(VendorSearch.WindowName .. "ItemNameText",name)
		end
		
		local slotName = parent.."Item"..i
		local elementName = parent.."Item"..i.."Name"
		local elementButton = parent.."Item"..i.."RemoveButton"
		CreateWindowFromTemplate(slotName, "ItemTemplateVS", parent)
		
		if i == 1 then
			WindowAddAnchor(slotName, "topleft", parent, "topleft", 10, 5)
			WindowAddAnchor(slotName, "topright", dialog, "topright", 0, 0)
		else
			WindowAddAnchor(slotName, "bottomleft", parent.."Item"..i-1, "topleft", 0, 10)
			WindowAddAnchor(slotName, "bottomright", dialog, "topright", 0, 0)
		end
		WindowSetScale(elementButton, 0.65)
		WindowSetId(elementButton,i)
		WindowSetHandleInput(slotName, true)
		
		local name = ReplaceTokens(GetStringFromTid(GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid), GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tidParms)
		if textParam then
			name = name .. textParam
		end
		LabelSetText(elementName, FormatProperly(name))
		
		local arr = {buttonId = i, labelId = j + 1, tid = GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tid, tidParams = GumpData.Gumps[VendorSearch.SearchGumpId].Labels[j + 1].tidParms, textParam = textParam, itsItemName = itemName}
		table.insert(VendorSearch.CurrentCriteriaButtons, arr)
		VendorSearch.OldCriteriaLabels = i
	end
	
	-- Fix Broken Gumps
	if(VendorSearch.PriceSortSet == 0) then
		local gumpID = VendorSearch.SearchGumpId
		if GumpsParsing.GumpMaps[gumpID] and GumpsParsing.GumpMaps[gumpID].name == "VendorSearch" then			
			GumpsParsing.GumpMaps[gumpID] = nil
		end	
		VendorSearch.ClearAll()		
		DestroyWindow(VendorSearch.WindowName)				
		return
	end

	
	if not (VendorSearch.CurrentCriteriaButtons[1] and VendorSearch.CurrentCriteriaButtons[1].itsItemName and VendorSearch.CurrentCriteriaButtons[1].itsItemName == TextEditBoxGetText(VendorSearch.WindowName .. "ItemNameText")) then
		TextEditBoxSetText(VendorSearch.WindowName .. "ItemNameText",L"")
	end
	
	local CategoryOffset = 0
	VendorSearch.CategoriesButtons = 
	{
		[1]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 1, buttonText = "price range", tid = 1154512};
		[2]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 2, buttonText = "miscellaneous", tid = 1011173};
		[3]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 3, buttonText = "equipment", tid = 1078237};
		[4]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 4, buttonText = "combat", tid = 1077417};
		[5]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 5, buttonText = "casting", tid = 1076209};
		[6]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 6, buttonText = "damage type", tid = 1154535};
		[7]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 7, buttonText = "hit spell", tid = 1154536};
		[8]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 8, buttonText = "hit area", tid = 1154537};
		[9]  = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 9, buttonText = "resists", tid = 1114254};
		[10] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 10, buttonText = "stats", tid = 1114262};
		[11] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 11, buttonText = "arachnid/reptile slayers", tid = 1154683};
		[12] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 12, buttonText = "repond/undead slayers", tid = 1154684};
		[13] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 13, buttonText = "demon/fey/elemental slayers", tid = 1154685};
		[14] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 14, buttonText = "required skill", tid = 1154543};
		[15] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 15, buttonText = "skill group 1", tid = 1114255};
		[16] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 16, buttonText = "skill group 2", tid = 1114256};
		[17] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 17, buttonText = "skill group 3", tid = 1114257};
		[18] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 18, buttonText = "skill group 4", tid = 1114258};
		[19] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 19, buttonText = "skill group 5", tid = 1114259};
		[20] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 20, buttonText = "skill group 6", tid = 1114260};
		[21] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 21, buttonText = "sort results", tid = 1154695};
		[22] = { buttonId = VendorSearch.TotalCriteria + CategoryOffset + 22, buttonText = "auction item", tid = 1159353};
	}
	-- VendorSearch.NumberOfCatagories == The number of elements in VendorSearch.CategoriesButtons + 1  
	
	local EquipmentOffset = 26
	VendorSearch.EquipmentButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 1, buttonText = "footwear/talons", tid = 1154602};
		[2]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 2, buttonText = "pants/leg armor", tid = 1154603};
		[3]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 3, buttonText = "shirt", tid = 1011359};
		[4]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 4, buttonText = "hat/head armor", tid = 1154605};
		[5]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 5, buttonText = "hand/kilt armor", tid = 1154606};
		[6]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 6, buttonText = "ring", tid = 1011207};
		[7]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 7, buttonText = "talisman", tid = 1024246};
		[8]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 8, buttonText = "necklace/neck armor", tid = 1154609};
		[9]  = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 9, buttonText = "apron/belt", tid = 1154611};
		[10] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 10, buttonText = "chest armor", tid = 1079904};
		[11] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 11, buttonText = "bracelet", tid = 1011219};
		[12] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 12, buttonText = "surcoat/tunic/sash", tid = 1154616};
		[13] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 13, buttonText = "earrings/gargish glasses", tid = 1154617};
		[14] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 14, buttonText = "arm armor", tid = 1079899};
		[15] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 15, buttonText = "cloak/quiver/wing armor", tid = 1154619};
		[16] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 16, buttonText = "dress/robe", tid = 1154621};
		[17] = { buttonId = VendorSearch.TotalCriteria + EquipmentOffset + 17, buttonText = "skirt", tid = 1011370};
	}
	
	local CombatOffset = 43
	VendorSearch.CombatButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 1,  buttonText = "damage increase", tid = 1062747, textboxId = 4};
		[2]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 2,  buttonText = "defense chance", tid = 1116527, textboxId = 5};
		[3]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 3,  buttonText = "hit chance", tid = 1116526, textboxId = 6};
		[4]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 4,  buttonText = "swing speed", tid = 1075629, textboxId = 7};
		[5]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 5,  buttonText = "soul charge", tid = 1116536, textboxId = 8};
		[6]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 6,  buttonText = "use best weapon skill", tid = 1079592};
		[7]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 7,  buttonText = "reactive paralyze", tid = 1112364};
		[8]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 8,  buttonText = "assassin honed", tid = 1152206};
		[9]  = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 9,  buttonText = "searing weapon", tid = 1151183};
		[10] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 10, buttonText = "blood drinker", tid = 1113591};
		[11] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 11, buttonText = "battle lust", tid = 1113710};
		[12] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 12, buttonText = "balanced", tid = 1072792};
		[13] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 13, buttonText = "focus", tid = 1044110, textboxId = 87};
		[14] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 14, buttonText = "fire eater", tid = 1075860, textboxId = 9};
		[15] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 15, buttonText = "cold eater", tid = 1154663, textboxId = 10};
		[16] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 16, buttonText = "poison eater", tid = 1154664, textboxId = 11};
		[17] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 17, buttonText = "energy eater", tid = 1154665, textboxId = 12};
		[18] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 18, buttonText = "kinetic eater", tid = 1154666, textboxId = 13};
		[19] = { buttonId = VendorSearch.TotalCriteria + CombatOffset + 19, buttonText = "damage eater", tid = 1154667, textboxId = 14};
	}
	
	local CastingOffset = 62
	VendorSearch.CastingButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 1,  buttonText = "fire resonance", tid = 1154655, textboxId = 15};
		[2]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 2,  buttonText = "cold resonance", tid = 1154656, textboxId = 16};
		[3]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 3,  buttonText = "poison resonance", tid = 1154657, textboxId = 17};
		[4]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 4,  buttonText = "energy resonance", tid = 1154658, textboxId = 18};
		[5]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 5,  buttonText = "kinetic resonance", tid = 1154659};
		[6]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 6,  buttonText = "spell damage increase", tid = 1062742, textboxId = 20};
		[7]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 7,  buttonText = "casting focus", tid = 1116535, textboxId = 21};
		[8]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 8,  buttonText = "faster cast recovery", tid = 1062743, textboxId = 22};
		[9]  = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 9,  buttonText = "faster casting", tid = 1062744, textboxId = 23};
		[10] = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 10, buttonText = "lower mana cost", tid = 1062745, textboxId = 24};
		[11] = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 11, buttonText = "lower reagent cost", tid = 1062757, textboxId = 25};
		[12] = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 12, buttonText = "mage weapon", tid = 1062755, textboxId = 26};
		[13] = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 13, buttonText = "mage armor", tid = 1060437};
		[14] = { buttonId = VendorSearch.TotalCriteria + CastingOffset + 14, buttonText = "spell channeling", tid = 1060482};
	}
	
	local MiscOffset = 76
	VendorSearch.MiscellaneousButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 1,  buttonText = "exclude items on felucca", tid = 1154646};
		[2]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 2,  buttonText = "gargoyles only", tid = 1111709};
		[3]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 3,  buttonText = "not gargoyles only", tid = 1154704};
		[4]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 4,  buttonText = "elves only", tid = 1075086};
		[5]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 5,  buttonText = "not elves only", tid = 1154703};
		[6]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 6,  buttonText = "faction item", tid = 1041350};
		[7]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 7,  buttonText = "promotional token", tid = 1154682};
		[8]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 8,  buttonText = "night sight", tid = 1015168};
		[9]  = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 9,  buttonText = "cursed", tid = 1049643};
		[10] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 10, buttonText = "not cursed", tid = 1154701};
		[11] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 11, buttonText = "cannot be repaired", tid = 1151782};
		[12] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 12, buttonText = "not cannot be repaired", tid = 1154705};
		[13] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 13, buttonText = "brittle", tid = 1116209};
		[14] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 14, buttonText = "not brittle", tid = 1154702};
		[15] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 15, buttonText = "antique", tid = 1152714};
		[16] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 16, buttonText = "not antique", tid = 1156479};		
		[17] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 17, buttonText = "enhance potions", tid = 1075624, textboxId = 27};
		[18] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 18, buttonText = "lower requirements", tid = 1062753, textboxId = 28};
		[19] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 19, buttonText = "luck", tid = 1061153, textboxId = 29};
		[20] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 20, buttonText = "reflect physical damage", tid = 1062738, textboxId = 30};
		[21] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 21, buttonText = "self repair", tid = 1079709, textboxId = 31};
		[22] = { buttonId = VendorSearch.TotalCriteria + MiscOffset + 22, buttonText = "artifact rarity", tid = 1154693, textboxId = 32};
	}
		
	local DamageTypeOffset = MiscOffset + 22
	VendorSearch.DamageTypeButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + DamageTypeOffset + 1, buttonText = "physical damage", tid = 1151800, textboxId = 33};
		[2] = { buttonId = VendorSearch.TotalCriteria + DamageTypeOffset + 2, buttonText = "cold damage", tid = 1151802, textboxId = 34};
		[3] = { buttonId = VendorSearch.TotalCriteria + DamageTypeOffset + 3, buttonText = "fire damage", tid = 1151801, textboxId = 35};
		[4] = { buttonId = VendorSearch.TotalCriteria + DamageTypeOffset + 4, buttonText = "poison damage", tid = 1151803, textboxId = 36};
		[5] = { buttonId = VendorSearch.TotalCriteria + DamageTypeOffset + 5, buttonText = "energy damage", tid = 1151804, textboxId = 37};
	}
	
	local HitSpellOffset = DamageTypeOffset + 5
	VendorSearch.HitSpellButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 1,  buttonText = "hit dispel", tid = 1079702, textboxId = 38};
		[2]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 2,  buttonText = "hit fireball", tid = 1079703, textboxId = 39};
		[3]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 3,  buttonText = "hit harm", tid = 1079704, textboxId = 40};
		[4]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 4,  buttonText = "hit curse", tid = 1154673, textboxId = 41};
		[5]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 5,  buttonText = "hit life leech", tid = 1079698, textboxId = 42};
		[6]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 6,  buttonText = "hit lightning", tid = 1079705, textboxId = 43};
		[7]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 7,  buttonText = "velocity", tid = 1080416, textboxId = 44};
		[8]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 8,  buttonText = "hit lower attack", tid = 1079699, textboxId = 45};
		[9]  = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 9,  buttonText = "hit lower defense", tid = 1079700, textboxId = 46};
		[10] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 10, buttonText = "hit magic arrow", tid = 1079706, textboxId = 47};
		[11] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 11, buttonText = "hit mana leech", tid = 1079701, textboxId = 48};
		[12] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 12, buttonText = "hit stamina leech", tid = 1079707, textboxId = 49};
		[13] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 13, buttonText = "hit fatigue", tid = 1154668, textboxId = 50};
		[14] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 14, buttonText = "hit mana drain", tid = 1154669, textboxId = 51};
		[15] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 15, buttonText = "splintering weapon", tid = 1154670};
		[16] = { buttonId = VendorSearch.TotalCriteria + HitSpellOffset + 16, buttonText = "bane", tid = 1154468};
	}		
													
	local HitAreaOffset = HitSpellOffset + 16
	VendorSearch.HitAreaButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + HitAreaOffset + 1, buttonText = "hit cold area", tid = 1079693, textboxId = 53};
		[2] = { buttonId = VendorSearch.TotalCriteria + HitAreaOffset + 2, buttonText = "hit energy area", tid = 1079694, textboxId = 54};
		[3] = { buttonId = VendorSearch.TotalCriteria + HitAreaOffset + 3, buttonText = "hit fire area", tid = 1079695, textboxId = 55};
		[4] = { buttonId = VendorSearch.TotalCriteria + HitAreaOffset + 4, buttonText = "hit physical area", tid = 1079696, textboxId = 56};
		[5] = { buttonId = VendorSearch.TotalCriteria + HitAreaOffset + 5, buttonText = "hit poison area", tid = 1079697, textboxId = 57};
	}
	
	local ResistOffset = HitAreaOffset + 5
	VendorSearch.ResistButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + ResistOffset + 1, buttonText = "cold resist", tid = 1062750, textboxId = 58};
		[2] = { buttonId = VendorSearch.TotalCriteria + ResistOffset + 2, buttonText = "energy resist", tid = 1062752, textboxId = 59};
		[3] = { buttonId = VendorSearch.TotalCriteria + ResistOffset + 3, buttonText = "fire resist", tid = 1062749, textboxId = 60};
		[4] = { buttonId = VendorSearch.TotalCriteria + ResistOffset + 4, buttonText = "physical resist", tid = 1062748, textboxId = 61};
		[5] = { buttonId = VendorSearch.TotalCriteria + ResistOffset + 5, buttonText = "poison resist", tid = 1062751, textboxId = 62};
	}
	
	local StatsOffset = ResistOffset + 5
	VendorSearch.StatsButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 1,  buttonText = "strength bonus", tid = 1062728, textboxId = 63};
		[2] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 2,  buttonText = "dexterity bonus", tid = 1062729, textboxId = 64};
		[3] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 3,  buttonText = "intelligence bonus", tid = 1062730, textboxId = 65};
		[4] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 4,  buttonText = "hit points increase", tid = 1079404, textboxId = 66};
		[5] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 5,  buttonText = "stamina increase", tid = 1062732, textboxId = 67};
		[6] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 6,  buttonText = "mana increase", tid = 1062733, textboxId = 68};
		[7] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 7,  buttonText = "hit point regeneration", tid = 1062734, textboxId = 69};
		[8] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 8,  buttonText = "stamina regeneration", tid = 1062756, textboxId = 70};
		[9] = { buttonId = VendorSearch.TotalCriteria + StatsOffset + 9,  buttonText = "mana regeneration", tid = 1062735, textboxId = 71};
	}
	
	local SlayersOffset = StatsOffset + 9
	VendorSearch.SlayersButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 30, buttonText = "air elemental slayer", tid = 1060457};
		[2]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 6, buttonText = "arachnid slayer", tid = 1060458};
		[3]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 11, buttonText = "bat slayer", tid = 1072506};
		[4]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 12, buttonText = "bear slayer", tid = 1072504};
		[5]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 13, buttonText = "beetle slayer", tid = 1072508};
		[6]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 14, buttonText = "bird slayer", tid = 1072509};
		[7]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 31, buttonText = "blood elemental slayer", tid = 1060459};
		[8]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 15, buttonText = "bovine slayer", tid = 1072512};
		[9]  = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 26, buttonText = "demon slayer", tid = 1060460};
		[10] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 2, buttonText = "dragon slayer", tid = 1060462};
		[11] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 32, buttonText = "earth elemental slayer", tid = 1060463};
		[12] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 29, buttonText = "elemental slayer", tid = 1060464};
		[13] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 28, buttonText = "fey slayer", tid = 1070855};
		[14] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 33, buttonText = "fire elemental slayer", tid = 1060465};
		[15] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 16, buttonText = "flame slayer", tid = 1072511};
		[16] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 27, buttonText = "gargoyle slayer", tid = 1060466};
		[17] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 17, buttonText = "goblin slayer", tid = 1095010};
		[18] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 18, buttonText = "ice slayer", tid = 1072510};
		[19] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 3, buttonText = "lizardman slayer", tid = 1060467};
		[20] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 19, buttonText = "mage slayer", tid = 1072507};
		[21] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 20, buttonText = "ogre slayer", tid = 1060468};
		[22] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 4, buttonText = "ophidian slayer", tid = 1060469};
		[23] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 21, buttonText = "orc slayer", tid = 1060470};
		[24] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 34, buttonText = "poison elemental slayer", tid = 1060471};
		[25] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 10, buttonText = "repond slayer", tid = 1060472};
		[26] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 1, buttonText = "reptile slayer", tid = 1060473};
		[27] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 7, buttonText = "scorpion slayer", tid = 1060474};
		[28] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 5, buttonText = "snake slayer", tid = 1060475};
		[29] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 35, buttonText = "snow elemental slayer", tid = 1079745 };
		[30] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 8, buttonText = "spider slayer", tid = 1060477};
		[31] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 9, buttonText = "terathan slayer", tid = 1060478};
		[32] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 22, buttonText = "troll slayer", tid = 1060480};
		[33] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 24, buttonText = "undead slayer", tid = 1060479};
		[34] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 23, buttonText = "vermin slayer", tid = 1072505};
		[35] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 36, buttonText = "water elemental slayer", tid = 1060481};
		[36] = { buttonId = VendorSearch.TotalCriteria + SlayersOffset + 25, buttonText = "wolf slayer", tid = 1075462};
	}
	
	local SkillReqOffset = SlayersOffset + 36
	VendorSearch.SkillReqButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + SkillReqOffset + 1, buttonText = "swordsmanship", tid = 1002151};
		[2] = { buttonId = VendorSearch.TotalCriteria + SkillReqOffset + 2, buttonText = "mace fighting", tid = 1002102};
		[3] = { buttonId = VendorSearch.TotalCriteria + SkillReqOffset + 3, buttonText = "fencing", tid = 1002073};
		[4] = { buttonId = VendorSearch.TotalCriteria + SkillReqOffset + 4, buttonText = "archery", tid = 1002029};
		[5] = { buttonId = VendorSearch.TotalCriteria + SkillReqOffset + 5, buttonText = "throwing", tid = 1044117};
	}
	
	local SkillsOffset = SkillReqOffset + 5
	VendorSearch.SkillsButtons = {
		[1]  = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 1", tid = 1114255};
		[2]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 1, buttonText = "swordsmanship", tid = 1002151, textboxId = 72};
		[3]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 2, buttonText = "fencing", tid = 1002073, textboxId = 73};
		[4]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 3, buttonText = "mace fighting", tid = 1002102, textboxId = 74};
		[5]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 4, buttonText = "magery", tid = 1002106, textboxId = 75};
		[6]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 5, buttonText = "musicianship", tid = 1002116, textboxId = 76};
		[7]  = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 2", tid = 1114256};
		[8]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 6, buttonText = "wrestling", tid = 1002169, textboxId = 77};
		[9]  = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 7, buttonText = "tactics", tid = 1017321, textboxId = 78};
		[10] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 8, buttonText = "animal taming", tid = 1002010, textboxId = 79};
		[11] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 9, buttonText = "provocation", tid = 1002125, textboxId = 80};
		[12] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 10, buttonText = "spirit speak", tid = 1002140, textboxId = 81};
		[13] = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 3", tid = 1114257};
		[14] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 11, buttonText = "stealth", tid = 1042394, textboxId = 82};
		[15] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 12, buttonText = "parrying", tid = 1002118, textboxId = 83};
		[16] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 13, buttonText = "meditation", tid = 1042393, textboxId = 84};
		[17] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 14, buttonText = "animal lore", tid = 1002007, textboxId = 85};
		[18] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 15, buttonText = "discordance", tid = 1042362, textboxId = 86};
		[19] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 16, buttonText = "focus", tid = 1044110, textboxId = 87};
		[20] = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 4", tid = 1114258};
		[21] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 17, buttonText = "stealing", tid = 1002142, textboxId = 88};
		[22] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 18, buttonText = "anatomy", tid = 1002004, textboxId = 89};
		[23] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 19, buttonText = "eval intelligence", tid = 1044076, textboxId = 90};
		[24] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 20, buttonText = "veterinary", tid = 1002167, textboxId = 91};
		[25] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 21, buttonText = "necromancy", tid = 1044109, textboxId = 92};
		[26] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 22, buttonText = "bushido", tid = 1044112, textboxId = 93};
		[27] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 23, buttonText = "mysticism", tid = 1044115, textboxId = 94};
		[28] = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 5", tid = 1114259};
		[29] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 24, buttonText = "healing", tid = 1002082, textboxId = 95};
		[30] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 25, buttonText = "resisting spells", tid = 1044086, textboxId = 96};
		[31] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 26, buttonText = "peacemaking", tid = 1002120, textboxId = 97};
		[32] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 27, buttonText = "archery", tid = 1002029, textboxId = 98};
		[33] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 28, buttonText = "chivalry", tid = 1044111, textboxId = 99};
		[34] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 29, buttonText = "ninjitsu", tid = 1044113, textboxId = 100};
		[35] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 30, buttonText = "throwing", tid = 1044117, textboxId = 101};
		[36] = { buttonId = VendorSearch.TotalCriteria + 0, buttonText = "skill group 6", tid = 1114260};
		[37] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 31, buttonText = "lumberjacking", tid = 1002100, textboxId = 102};
		[38] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 32, buttonText = "snooping", tid = 1002138, textboxId = 103};
		[39] = { buttonId = VendorSearch.TotalCriteria + SkillsOffset + 33, buttonText = "mining", tid = 1002111, textboxId = 104};
	}
	
	VendorSearch.IgnoreSkillsButton = { -- index of the previous array to be used only as description.
	[1] = true,
	[7] = true,
	[13] = true,
	[20] = true,
	[28] = true,
	[36] = true,
	}
	
	
	local PriceOffset = SkillsOffset + 33
	VendorSearch.PriceButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + PriceOffset + 1, buttonText = "price: low to high", tid = 1154696};
		[2] = { buttonId = VendorSearch.TotalCriteria + PriceOffset + 2, buttonText = "price: high to low", tid = 1154697};
	}

	local AuctionOffset = PriceOffset + 2
	VendorSearch.AuctionButtons = {
		[1] = { buttonId = VendorSearch.TotalCriteria + AuctionOffset + 1, buttonText = "Non Auction Item", tid = 1159354};
		[2] = { buttonId = VendorSearch.TotalCriteria + AuctionOffset + 2, buttonText = "Auction Item", tid = 1159353};
	}
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "MiscCombo")
	for i=1, #VendorSearch.MiscellaneousButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "MiscCombo", FormatProperly(GetStringFromTid(VendorSearch.MiscellaneousButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "EquipCombo")
	for i=1, #VendorSearch.EquipmentButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "EquipCombo", FormatProperly(GetStringFromTid(VendorSearch.EquipmentButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "CombatCombo")
	for i=1, #VendorSearch.CombatButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "CombatCombo", FormatProperly(GetStringFromTid(VendorSearch.CombatButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "CastingCombo")
	for i=1, #VendorSearch.CastingButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "CastingCombo", FormatProperly(GetStringFromTid(VendorSearch.CastingButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "SlayersCombo")
	for i=1, #VendorSearch.SlayersButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "SlayersCombo", FormatProperly(GetStringFromTid(VendorSearch.SlayersButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "ResistCombo")
	for i=1, #VendorSearch.ResistButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "ResistCombo", FormatProperly(GetStringFromTid(VendorSearch.ResistButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "StatsCombo")
	for i=1, #VendorSearch.StatsButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "StatsCombo", FormatProperly(GetStringFromTid(VendorSearch.StatsButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "SkillsCombo")
	for i=1, #VendorSearch.SkillsButtons do
		if VendorSearch.IgnoreSkillsButton[i] then
			ComboBoxAddMenuItem(VendorSearch.WindowName .. "SkillsCombo", L"---" .. FormatProperly(GetStringFromTid(VendorSearch.SkillsButtons[i].tid) .. L"---" ))
		else
			ComboBoxAddMenuItem(VendorSearch.WindowName .. "SkillsCombo", FormatProperly(GetStringFromTid(VendorSearch.SkillsButtons[i].tid)))
		end
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "HitSpellCombo")
	for i=1, #VendorSearch.HitSpellButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "HitSpellCombo", FormatProperly(GetStringFromTid(VendorSearch.HitSpellButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "HitAreaCombo")
	for i=1, #VendorSearch.HitAreaButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "HitAreaCombo", FormatProperly(GetStringFromTid(VendorSearch.HitAreaButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "SkillReqCombo")
	for i=1, #VendorSearch.SkillReqButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "SkillReqCombo", FormatProperly(GetStringFromTid(VendorSearch.SkillReqButtons[i].tid) ))
	end
	
	ComboBoxClearMenuItems(VendorSearch.WindowName .. "DamageTypeCombo")
	for i=1, #VendorSearch.DamageTypeButtons do
		ComboBoxAddMenuItem(VendorSearch.WindowName .. "DamageTypeCombo", FormatProperly(GetStringFromTid(VendorSearch.DamageTypeButtons[i].tid) ))
	end
end

function VendorSearch.RemoveCriteriaTooltip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1155388))

	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function VendorSearch.RemoveCriteria()
	local id = WindowGetId(SystemData.ActiveWindow.name)
	if VendorSearch.CurrentCriteriaButtons[id].itsItemName then
		TextEditBoxSetText(VendorSearch.WindowName .. "ItemNameText", L"")
	end
	VendorSearch.SetLoading(true)
	GumpsParsing.PressButton(VendorSearch.SearchGumpId, id)
end

function VendorSearch.LowHighButtonTooltip()
	if VendorSearch.PriceLowToHigh then
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1154696))
	else
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1154697))
	end

	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function VendorSearch.LowHighButton()
	local id = WindowGetId(SystemData.ActiveWindow.name)
	VendorSearch.SetLoading(true)
	local myId = VendorSearch.PriceButtons[1].buttonId	
	myId = VendorSearch.PriceButtons[2].buttonId	

	if not VendorSearch.PriceLowToHigh then
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.PriceButtons[1].buttonId)
	else
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.PriceButtons[2].buttonId)
	end
end

function VendorSearch.ToggleAuctionButtonTooltip()
	if VendorSearch.IsAuctionSearch then
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1159353))
	else
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1159354))
	end

	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function VendorSearch.ToggleAuctionButton()
	local id = WindowGetId(SystemData.ActiveWindow.name)
	VendorSearch.SetLoading(true)
	local myId = VendorSearch.AuctionButtons[1].buttonId	
	myId = VendorSearch.AuctionButtons[2].buttonId	
	if VendorSearch.IsAuctionSearch then
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.AuctionButtons[1].buttonId)
	else
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.AuctionButtons[2].buttonId)
	end
end

function VendorSearch.OnItemNameTextChanged(text)	
	TextEditBoxSetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[1], text)
	if wstring.len(text) <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "ItemNameButton", false)
	else
		WindowSetShowing(VendorSearch.WindowName .. "ItemNameButton", true)
	end
end

function VendorSearch.SearchName()
	VendorSearch.SetLoading(true)
	if VendorSearch.PriceLowToHigh then		
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.PriceButtons[1].buttonId)
	else		
		GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.PriceButtons[2].buttonId)
	end
end

function VendorSearch.ADDButtonTooltip()

	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1154534))

	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function VendorSearch.OnMinPriceTextChanged(text)
	TextEditBoxSetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[2], text)
	if wstring.len(text) <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", false)
	else
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", true)
	end
end

function VendorSearch.OnMaxPriceTextChanged(text)
	TextEditBoxSetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[3], text)
	if wstring.len(text) <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", false)
	else
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", true)
	end
end

function VendorSearch.SearchPrice()
	VendorSearch.SetLoading(true)
	GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.ConfirmPriceRange)

end

function VendorSearch.OnTextChanged(text)
	local txtId = WindowGetId(SystemData.ActiveWindow.name)
	local txt = string.gsub(string.gsub(SystemData.ActiveWindow.name, "Text", ""), VendorSearch.WindowName, "")
	if txtId ~= 0 then
		TextEditBoxSetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[txtId], text)
		if wstring.len(text) <= 0 then
			WindowSetShowing(VendorSearch.WindowName .. txt .. "Button", false)
		else
			WindowSetShowing(VendorSearch.WindowName .. txt .. "Button", true)
		end
	else
		WindowSetShowing(VendorSearch.WindowName .. txt .. "Text", false)
		WindowSetShowing(VendorSearch.WindowName .. txt .. "TextBG", false)
	end
	
end

function VendorSearch.SearchCombo()
	VendorSearch.SetLoading(true)
	local combo = string.gsub(string.gsub(SystemData.ActiveWindow.name, "Text", ""), VendorSearch.WindowName, "")
	combo = string.gsub(string.gsub(combo, "Button", ""), VendorSearch.WindowName, "")
	combo = VendorSearch.WindowName .. combo .. "Button"

	GumpsParsing.PressButton(VendorSearch.SearchGumpId, WindowGetId(combo))

end

function VendorSearch.OnComboSelChanged( selectedIndex )
	
	local combo = string.gsub(string.gsub(SystemData.ActiveWindow.name, "Combo", ""), VendorSearch.WindowName, "")
	local array
	local hasTbx = true
	if combo == "Misc" then
		array = VendorSearch.MiscellaneousButtons
	elseif combo == "Equip" then
		array = VendorSearch.EquipmentButtons
		hasTbx = false
	elseif combo == "Combat" then
		array = VendorSearch.CombatButtons
	elseif combo == "Casting" then
		array = VendorSearch.CastingButtons
	elseif combo == "Slayers" then
		array = VendorSearch.SlayersButtons
	elseif combo == "Resist" then
		array = VendorSearch.ResistButtons
	elseif combo == "Stats" then
		array = VendorSearch.StatsButtons
	elseif combo == "Skills" then
		array = VendorSearch.SkillsButtons
	elseif combo == "HitSpell" then
		array = VendorSearch.HitSpellButtons
	elseif combo == "HitArea" then
		array = VendorSearch.HitAreaButtons
	elseif combo == "SkillReq" then
		array = VendorSearch.SkillReqButtons
	elseif combo == "DamageType" then
		array = VendorSearch.DamageTypeButtons
	end

	if array[selectedIndex].buttonId == VendorSearch.TotalCriteria then
		ComboBoxSetSelectedMenuItem( SystemData.ActiveWindow.name, 0 )
	end
	WindowSetId(VendorSearch.WindowName .. combo .. "Button", array[selectedIndex].buttonId)
	if hasTbx and array[selectedIndex].textboxId and array[selectedIndex].buttonId > 0 and array[selectedIndex].buttonId ~= VendorSearch.TotalCriteria then
		WindowSetId(VendorSearch.WindowName .. combo .. "Text", array[selectedIndex].textboxId)
		TextEditBoxSetText(VendorSearch.WindowName .. combo .. "Text", TextEditBoxGetText(GumpData.Gumps[VendorSearch.SearchGumpId].TextEntry[array[selectedIndex].textboxId]))
		WindowSetShowing(VendorSearch.WindowName .. combo .. "Text", true)
		WindowSetShowing(VendorSearch.WindowName .. combo .. "TextBG", true)
		WindowAssignFocus(VendorSearch.WindowName .. combo .. "Text", true)
		WindowSetShowing(VendorSearch.WindowName .. combo .. "Button", true)
	elseif hasTbx or array[selectedIndex].buttonId == VendorSearch.TotalCriteria then
		WindowSetShowing(VendorSearch.WindowName .. combo .. "Text", false)
		WindowSetShowing(VendorSearch.WindowName .. combo .. "TextBG", false)
	end
end

function VendorSearch.ClearAll()
	VendorSearch.SetLoading(true)
	GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.ClearSearch)
end

function VendorSearch.SearchThis()
	VendorSearch.SetLoading(true)
	GumpsParsing.PressButton(VendorSearch.SearchGumpId, VendorSearch.Search)
end

VendorSearch.CriteriaBlink = false
function VendorSearch.OnUpdate(timePassed)
	
	if VendorSearch.TotalCriteria < VendorSearch.TotalCriteriaExpected  or WindowGetAlpha(VendorSearch.WindowName .. "OtherError") > 0 then
		WindowSetShowing(VendorSearch.WindowName .. "CriteriaMax", false)
		if VendorSearch.CriteriaBlink then
			WindowStopAlphaAnimation(VendorSearch.WindowName .. "CriteriaMax")
			VendorSearch.CriteriaBlink = false
		end
	elseif WindowGetAlpha(VendorSearch.WindowName .. "OtherError") == 0 then
		WindowSetShowing(VendorSearch.WindowName .. "CriteriaMax", true)
		if not VendorSearch.CriteriaBlink then
			WindowStartAlphaAnimation(VendorSearch.WindowName .. "CriteriaMax", Window.AnimationType.LOOP, 0.3, 1, 1, false, 0, 0)
			VendorSearch.CriteriaBlink = true
		end
	end
	
	if WindowHasFocus(VendorSearch.WindowName .. "ItemNameText") then
		WindowSetShowing(VendorSearch.WindowName .. "ItemNameButton", true)
	elseif not WindowHasFocus(VendorSearch.WindowName .. "ItemNameText") and (wstring.len(TextEditBoxGetText(VendorSearch.WindowName .. "ItemNameText")) <= 0 or (VendorSearch.CurrentCriteriaButtons[1] and VendorSearch.CurrentCriteriaButtons[1].itsItemName and VendorSearch.CurrentCriteriaButtons[1].itsItemName == TextEditBoxGetText(VendorSearch.WindowName .. "ItemNameText"))) then
		WindowSetShowing(VendorSearch.WindowName .. "ItemNameButton", false)
	end
	
	local minn = string.gsub(tostring(TextEditBoxGetText(VendorSearch.WindowName .. "MinPriceText")), ",", "")
	minn = tonumber(minn)
	
	local maxx = string.gsub(tostring(TextEditBoxGetText(VendorSearch.WindowName .. "MaxPriceText")), ",", "")
	maxx = tonumber(maxx)
	
	if WindowHasFocus(VendorSearch.WindowName .. "MinPriceText") then
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", true)
	elseif WindowHasFocus(VendorSearch.WindowName .. "MaxPriceText")  then
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", true)
	elseif (not WindowHasFocus(VendorSearch.WindowName .. "MinPriceText") and (wstring.len(TextEditBoxGetText(VendorSearch.WindowName .. "MinPriceText")) <= 0 or VendorSearch.PriceRange.min == minn)) and
		   (not WindowHasFocus(VendorSearch.WindowName .. "MaxPriceText") and (wstring.len(TextEditBoxGetText(VendorSearch.WindowName .. "MaxPriceText")) <= 0 or VendorSearch.PriceRange.max == maxx))
			then
			
		WindowSetShowing(VendorSearch.WindowName .. "PriceRangeButton", false)
	end
		
	local Equip = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "EquipCombo")
	if Equip <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "EquipButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "EquipButton", true)
	end
	
	local misc = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "MiscCombo")
	if misc <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "MiscText", false)
		WindowSetShowing(VendorSearch.WindowName .. "MiscTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "MiscButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "MiscButton", true)
	end
	
	local Combat = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "CombatCombo")
	if Combat <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "CombatText", false)
		WindowSetShowing(VendorSearch.WindowName .. "CombatTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "CombatButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "CombatButton", true)
	end
	
	local Casting = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "CastingCombo")
	if Casting <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "CastingText", false)
		WindowSetShowing(VendorSearch.WindowName .. "CastingTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "CastingButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "CastingButton", true)
	end
	
	local Slayers = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "SlayersCombo")
	if Slayers <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "SlayersText", false)
		WindowSetShowing(VendorSearch.WindowName .. "SlayersTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "SlayersButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "SlayersButton", true)
	end
	
	local Resist = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "ResistCombo")
	if Resist <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "ResistText", false)
		WindowSetShowing(VendorSearch.WindowName .. "ResistTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "ResistButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "ResistButton", true)
	end
	
	local Stats = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "StatsCombo")
	if Stats <= 0 then
		WindowSetShowing(VendorSearch.WindowName .. "StatsText", false)
		WindowSetShowing(VendorSearch.WindowName .. "StatsTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "StatsButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "StatsButton", true)
	end
	
	local Skills = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "SkillsCombo")
	if Skills <= 0 or VendorSearch.SkillsButtons[Skills].buttonId == VendorSearch.TotalCriteria then
		WindowSetShowing(VendorSearch.WindowName .. "SkillsText", false)
		WindowSetShowing(VendorSearch.WindowName .. "SkillsTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "SkillsButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "SkillsButton", true)
	end
	
	local HitSpell = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "HitSpellCombo")
	if HitSpell <= 0 or VendorSearch.HitSpellButtons[HitSpell].buttonId == VendorSearch.TotalCriteria  then
		WindowSetShowing(VendorSearch.WindowName .. "HitSpellText", false)
		WindowSetShowing(VendorSearch.WindowName .. "HitSpellTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "HitSpellButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "HitSpellButton", true)
	end
	
	local HitArea = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "HitAreaCombo")
	if HitArea <= 0 or VendorSearch.HitAreaButtons[HitArea].buttonId == VendorSearch.TotalCriteria then
		WindowSetShowing(VendorSearch.WindowName .. "HitAreaText", false)
		WindowSetShowing(VendorSearch.WindowName .. "HitAreaTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "HitAreaButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "HitAreaButton", true)
	end
	
	local SkillReq = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "SkillReqCombo")
	if SkillReq <= 0 or VendorSearch.SkillReqButtons[SkillReq].buttonId == VendorSearch.TotalCriteria then
		WindowSetShowing(VendorSearch.WindowName .. "SkillReqText", false)
		WindowSetShowing(VendorSearch.WindowName .. "SkillReqTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "SkillReqButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "SkillReqButton", true)
	end
	
	local DamageType = ComboBoxGetSelectedMenuItem(VendorSearch.WindowName .. "DamageTypeCombo")
	if DamageType <= 0 or VendorSearch.DamageTypeButtons[DamageType].buttonId == VendorSearch.TotalCriteria then
		WindowSetShowing(VendorSearch.WindowName .. "DamageTypeText", false)
		WindowSetShowing(VendorSearch.WindowName .. "DamageTypeTextBG", false)
		WindowSetShowing(VendorSearch.WindowName .. "DamageTypeButton", false)		
	else
		WindowSetShowing(VendorSearch.WindowName .. "DamageTypeButton", true)
	end
end

function VendorSearch.SetLoading(load)	
end

