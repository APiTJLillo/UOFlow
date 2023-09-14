
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

QuickStats = {}

QuickStats.Settings = {}
QuickStats.Initialized = false

QuickStats.LabelsRefreshRate = 1

-- [LabeID] = {attribute=AttributeName, objectType=TypeID, minQuantity=MinQuantityWarningAmount, icon=ON/OFF, frame=ON/OFF name=ON/OFF, cap=ON/OFF, locked=ON/OFF, BGColor=RGB, frameColor=RGB, valueTextColor=RGB, nameTextColor=RGB}
QuickStats.Labels = {}

QuickStats.Max = 100

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------


function QuickStats.Initialize()
	
	
	QuickStats.Labels = {}
	for i = 1, QuickStats.Max do
		local label = "QuickStat_" .. i
		local lab = QuickStats.Load(label)
		QuickStats.Labels[i] = lab
		if lab then
			local label = "QuickStat_" .. i
			CreateWindowFromTemplate(label, "QuickStatTemplate", "Root")
			WindowUtils.openWindows[label] = true
			WindowSetId(label, i)
			
			SnapUtils.SnappableWindows[label] = true
			
			WindowSetOffsetFromParent(label, lab.x, lab.y)
		
			QuickStats.UpdateLabel(label)
			
			WindowUtils.LoadScale( label )		
		end
	end
	QuickStats.Initialized = true
end

function QuickStats.Shutdown()
	for i = 1, QuickStats.Max do
		local label = "QuickStat_" .. i
		if DoesWindowNameExist(label) then
			QuickStats.Save(label)
			DestroyWindow(label)
		end
	end
	QuickStats.Initialized = false
end

function QuickStats.GetId()
	for i = 1, QuickStats.Max do
		if not QuickStats.Labels[i] then
			return i
		end
	end
end

function QuickStats.Save(label)
	--Debug.Print("Saving:"..label)
	local lab = QuickStats.Labels[WindowGetId(label)]
	local x, y = WindowGetOffsetFromParent(label)
	lab.x = x
	lab.y = y
	lab.blink = nil
	if lab.attribute then
		Interface.SaveNumber(label .. "_attribute", lab.attribute)
	end
	if lab.objectType then
		Interface.SaveNumber(label .. "_objectType", lab.objectType)
	end
	Interface.SaveNumber(label .. "_minQuantity", lab.minQuantity)
	Interface.SaveBoolean(label .. "_icon", lab.icon)
	Interface.SaveBoolean(label .. "_frame", lab.frame)
	Interface.SaveBoolean(label .. "_name", lab.name)
	Interface.SaveBoolean(label .. "_cap", lab.cap)
	Interface.SaveBoolean(label .. "_locked", lab.locked)
	Interface.SaveColor(label .. "_BGColor", lab.BGColor)
	Interface.SaveColor(label .. "_frameColor", lab.frameColor)
	Interface.SaveColor(label .. "_valueTextColor", lab.valueTextColor)
	Interface.SaveColor(label .. "_nameTextColor", lab.nameTextColor)	
	Interface.SaveNumber(label .. "_x", lab.x)	
	Interface.SaveNumber(label .. "_y", lab.y)	
end

function QuickStats.Load(label)
	--Debug.Print("Loading:"..label)
	local lab = {}
	lab.attribute = Interface.LoadNumber(label .. "_attribute", nil)
	lab.objectType = Interface.LoadNumber(label .. "_objectType", nil)
	lab.minQuantity = Interface.LoadNumber(label .. "_minQuantity", nil)
	lab.icon = Interface.LoadBoolean(label .. "_icon", nil)
	lab.frame = Interface.LoadBoolean(label .. "_frame", nil)
	lab.name = Interface.LoadBoolean(label .. "_name", nil)
	lab.cap = Interface.LoadBoolean(label .. "_cap", nil)
	lab.locked = Interface.LoadBoolean(label .. "_locked", nil)
	lab.BGColor = Interface.LoadColor(label .. "_BGColor", nil)
	lab.frameColor = Interface.LoadColor(label .. "_frameColor", nil)
	lab.valueTextColor = Interface.LoadColor(label .. "_valueTextColor", nil)
	lab.nameTextColor = Interface.LoadColor(label .. "_nameTextColor", nil)	
	lab.x = Interface.LoadNumber(label .. "_x", nil)
	lab.y = Interface.LoadNumber(label .. "_y", nil)
	lab.blink = false
	if not lab.BGColor then
		lab = nil
	end
	return lab
end

function QuickStats.DeleteSettings(label)

	Interface.DeleteSetting(label .. "_attribute")
	Interface.DeleteSetting(label .. "_objectType")
	Interface.DeleteSetting(label .. "_minQuantity")
	Interface.DeleteSetting(label .. "_icon")
	Interface.DeleteSetting(label .. "_frame")
	Interface.DeleteSetting(label .. "_name")
	Interface.DeleteSetting(label .. "_cap")
	Interface.DeleteSetting(label .. "_locked")
	Interface.DeleteSetting(label .. "_BGColor")
	Interface.DeleteSetting(label .. "_frameColor")
	Interface.DeleteSetting(label .. "_valueTextColor")
	Interface.DeleteSetting(label .. "_nameTextColor")	
	Interface.DeleteSetting(label .. "_x")	
	Interface.DeleteSetting(label .. "_y")	
	
	QuickStats.Labels[WindowGetId(label)] = nil	
	Interface.DeleteSetting( label .."SC" )
	DestroyWindow(label)
	WindowUtils.openWindows[label] = nil
end


function QuickStats.DoesLabelExist(attributeId, isObject)
	for i,_ in pairs(QuickStats.Labels) do
		local lab = QuickStats.Labels[i]
		if lab and lab.attribute == attributeId and not isObject then
			return i
		elseif lab and lab.objectType == attributeId and isObject then
			return i
		end
	end
	return 0
end
function QuickStats.UpdateLabel(label)
	if not DoesWindowNameExist(label) then
		return
	end
	if not label or WindowGetId(label) == 0 then
		return
	end
	local lab = QuickStats.Labels[WindowGetId(label)]
	if not lab then
		return
	end
	local id = lab.attribute
	
	local isObject = false
	
	if lab.objectType then
		id = lab.objectType
		isObject = true
	end
	
	if not lab.minQuantity then
		lab.minQuantity = -1
	end
	
	local tid
	local yOffset = 0
	local xOffset = 0
	if isObject then
		WindowUtils.DrawObjectIcon(id, 0, label.."SquareIcon")
		tid = ItemsInfo.Reagents[id]
		
		WindowClearAnchors(label.."SquareIcon")
		WindowAddAnchor(label.."SquareIcon", "left", label, "left", 6, 5)
		yOffset = -5
	else
		CharacterSheet.SetMiniIconStats(label, WindowData.PlayerStatsDataCSV[id].iconId)
		tid = WindowData.PlayerStatsDataCSV[id].tid
		
		WindowClearAnchors(label.."AttributeName")
		WindowAddAnchor(label.."AttributeName", "right", label.."SquareIcon", "left", 6, 0)
	end
	
	local labelName = label.."AttributeName"
	
	LabelSetTextColor(label.."AttributeName", lab.nameTextColor.r,lab.nameTextColor.g,lab.nameTextColor.b)
	
	local sep = CharacterSheet.Separators[k] or "/"
	local value
	local cap = ""
	if isObject then
		local qta = 0
		if Interface.BackPackItems then
			for i = 1, #Interface.BackPackItems do
				local updateId = Interface.BackPackItems[i]				
				if WindowData.ObjectInfo[updateId] and WindowData.ObjectInfo[updateId].objectType == id then
					qta = qta + WindowData.ObjectInfo[updateId].quantity
				end
			end
		end
		value = tostring(Knumber(tonumber(tostring(qta))))		
		if lab.minQuantity ~= -1 and lab.minQuantity >= qta and not lab.blink then
			LabelSetTextColor(label.."AttributeValue", 255,0,0)
			WindowStartAlphaAnimation(label.."AttributeValue", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
			
			LabelSetTextColor(label.."AttributeName", 255,0,0)
			WindowStartAlphaAnimation(label.."AttributeName", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
			lab.blink = true
		elseif ((lab.minQuantity < qta and lab.blink) or lab.minQuantity == -1) then
			LabelSetTextColor(label.."AttributeValue", lab.valueTextColor.r,lab.valueTextColor.g,lab.valueTextColor.b)
			WindowStopAlphaAnimation(label.."AttributeValue")
			
			LabelSetTextColor(label.."AttributeName", lab.nameTextColor.r,lab.nameTextColor.g,lab.nameTextColor.b)
			WindowStopAlphaAnimation(label.."AttributeName")
			lab.blink = nil
		end		
		sep = ""
	else
		local k = tostring(WindowData.PlayerStatsDataCSV[id].name)
		if k == "ColdResist" then
			xOffset = -5
		end
		local curVar = k
		if( k == "Health" or k == "Stamina" or k == "Mana" ) then
			curVar = "Current"..k
		end
		
		if (k == "Weight") then
			lab.minQuantity = tonumber(tostring(WindowData.PlayerStatus["Max"..k])) - HotbarSystem.WARNINGLEVEL
		end
		
		value = tostring(Knumber(tonumber(tostring(WindowData.PlayerStatus[curVar]))), true)
		if lab.cap then			
			if (CharacterSheet.Caps[k]) then
				cap = CharacterSheet.Caps[k] + CharacterSheet.CapsBonus[k]
			end
			
			if WindowData.PlayerStatus["Max"..k] then
				cap = tostring(Knumber(tonumber(tostring(WindowData.PlayerStatus["Max"..k])), true))	
			end
			if(k == "Damage") then
				sep = "-"
			end

			if(cap=="")then
				sep = ""
			end
		else
			sep = ""
		end
		
		local qta = tonumber(tostring(WindowData.PlayerStatus[curVar]))
		if (k == "Weight") then
			if qta >= lab.minQuantity then
				if not lab.blink then
					LabelSetTextColor(label.."AttributeValue", 255,0,0)
					WindowStartAlphaAnimation(label.."AttributeValue", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
					
					LabelSetTextColor(label.."AttributeName", 255,0,0)
					WindowStartAlphaAnimation(label.."AttributeName", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
					lab.blink = true
				end
				if string.find(value, "K") then
					cap = ""
					sep = ""
				end
			elseif (qta < lab.minQuantity and lab.blink) then
				LabelSetTextColor(label.."AttributeValue", lab.valueTextColor.r,lab.valueTextColor.g,lab.valueTextColor.b)
				WindowStopAlphaAnimation(label.."AttributeValue")
				
				LabelSetTextColor(label.."AttributeName", lab.nameTextColor.r,lab.nameTextColor.g,lab.nameTextColor.b)
				WindowStopAlphaAnimation(label.."AttributeName")
				lab.blink = nil
			end
		else
			if lab.minQuantity ~= -1 and lab.minQuantity >= qta and not lab.blink then
				LabelSetTextColor(label.."AttributeValue", 255,0,0)
				WindowStartAlphaAnimation(label.."AttributeValue", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
				
				LabelSetTextColor(label.."AttributeName", 255,0,0)
				WindowStartAlphaAnimation(label.."AttributeName", Window.AnimationType.LOOP, 0.3, 1.0, 1, false, 0, 0)
				lab.blink = true
			elseif ((lab.minQuantity < qta and lab.blink) or lab.minQuantity == -1) then
				LabelSetTextColor(label.."AttributeValue", lab.valueTextColor.r,lab.valueTextColor.g,lab.valueTextColor.b)
				WindowStopAlphaAnimation(label.."AttributeValue")
				
				LabelSetTextColor(label.."AttributeName", lab.nameTextColor.r,lab.nameTextColor.g,lab.nameTextColor.b)
				WindowStopAlphaAnimation(label.."AttributeName")
				lab.blink = nil
			end
		end
	end

	LabelSetText(label.."AttributeValue", towstring(value .. sep .. cap))
	LabelSetTextColor(label.."AttributeValue", lab.valueTextColor.r,lab.valueTextColor.g,lab.valueTextColor.b)
	
	local yOffset = 0
	if isObject then
		WindowClearAnchors(label.."SquareIcon")
		WindowAddAnchor(label.."SquareIcon", "left", label, "left", 6, 5)
		yOffset = -5
	else
	
		WindowClearAnchors(label.."AttributeName")
		WindowAddAnchor(label.."AttributeName", "right", label.."SquareIcon", "left", 6, 0)
	end
	
	
	local w, _ = WindowGetDimensions(label.."AttributeName")
	w = w + 10
	local w1, _ = WindowGetDimensions(label.."AttributeValue")
	w1 = w1 + 10
	local w2, _ = WindowGetDimensions(label.."SquareIcon")
	w2 = w2 + 6
	
	local totalW

	if lab.icon then
		WindowSetShowing(label.."SquareIcon", true)
		
		if lab.name then
			LabelSetText(label.."AttributeName", GetStringFromTid(tid))
			local w, h = LabelGetTextDimensions(label.."AttributeName")
			w = 190
			WindowSetDimensions(label.."AttributeName", w, h)
			WindowClearAnchors(label.."AttributeName")
			WindowAddAnchor(label.."AttributeName", "right", label.."SquareIcon", "left", 6, yOffset)
			
			w1 = 70
			WindowSetDimensions(label.."AttributeValue", w1, h)			
			WindowClearAnchors(label.."AttributeValue")
			WindowAddAnchor(label.."AttributeValue", "right", label.."AttributeName", "left", xOffset, 0)
			LabelSetTextAlign(label.."AttributeValue", "right")
			
			totalW = w + w1+ w2 + 18
		else
			LabelSetText(label.."AttributeName", L"")			
			local w1, h = LabelGetTextDimensions(label.."AttributeValue")
			w1 = 65
			if not lab.cap then
				w1 = w1/2
			end
			WindowSetDimensions(label.."AttributeValue", w1, h)
			WindowClearAnchors(label.."AttributeValue")
			WindowAddAnchor(label.."AttributeValue", "right", label.."SquareIcon", "left", xOffset + 6, yOffset)
			LabelSetTextAlign(label.."AttributeValue", "right")
			
			totalW = w1+ w2 + 18
		end
		
	else
		WindowSetShowing(label.."SquareIcon", false)
		if lab.name then
			LabelSetText(label.."AttributeName", GetStringFromTid(tid))
			local w, h = LabelGetTextDimensions(label.."AttributeName")
			w = 190
			WindowSetDimensions(label.."AttributeName", w, h)
			WindowClearAnchors(label.."AttributeName")
			WindowAddAnchor(label.."AttributeName", "left", label, "left", 6, 0)
			
			w1 = 65
			WindowSetDimensions(label.."AttributeValue", w1, h)
			
			WindowClearAnchors(label.."AttributeValue")
			WindowAddAnchor(label.."AttributeValue", "right", label.."AttributeName", "left", 0, 0)
			LabelSetTextAlign(label.."AttributeValue", "right")
			
			totalW = w + w1 + 18
		else
			LabelSetText(label.."AttributeName", L"")			
			local w1, h = LabelGetTextDimensions(label.."AttributeValue")
			WindowSetDimensions(label.."AttributeValue", w1, h)
			WindowClearAnchors(label.."AttributeValue")
			WindowAddAnchor(label.."AttributeValue", "left", label, "left", 6, 0)
			LabelSetTextAlign(label.."AttributeValue", "left")
			local off = 12
			if lab.cap then
				off = off/2
			end
			totalW = w1 + off
		end
	end

	WindowSetDimensions(label, totalW, 30)
	WindowForceProcessAnchors(label)
	
	WindowSetAlpha(label.."WindowBackground", 0.8)
	WindowSetTintColor(label.."WindowBackground", lab.BGColor.r,lab.BGColor.g,lab.BGColor.b)
	
	if not lab.frame then
		WindowSetShowing(label.."Frame", false)
	else
		WindowSetShowing(label.."Frame", true)
		WindowSetAlpha(label.."Frame", 0.8)
		WindowSetTintColor(label.."Frame", lab.frameColor.r,lab.frameColor.g,lab.frameColor.b)
	end
end

QuickStats.Delta = 0
function QuickStats.OnUpdate(timePassed)
	QuickStats.Delta = QuickStats.Delta + timePassed
	if QuickStats.Delta > QuickStats.LabelsRefreshRate then
		QuickStats.Delta = 0
		for i = 1, QuickStats.Max do
			local label = "QuickStat_" .. i
			if DoesWindowNameExist(label) and QuickStats.InMovement[label] ~= true and label ~= SnapUtils.SnapWindow then
				QuickStats.UpdateLabel(label)
			end
		end
	end
end

function QuickStats.StatLButtonDown(flags)	
	local this = WindowGetParent(SystemData.ActiveWindow.name)	
	local id = WindowGetId(this)
	if flags == SystemData.ButtonFlags.SHIFT and not WindowGetMoving(this) then		
		QuickStats.FindQuickStatMovingBlock(this)
		QuickStats.InMovement[this] = true
	elseif QuickStats.Labels[id] and not QuickStats.Labels[id].locked and not WindowGetMoving(this) then		
		QuickStats.InMovement[this] = true
		SnapUtils.StartWindowSnap(this)
		WindowSetMoving(this, true)
	end
end

function QuickStats.StatOnLButtonUp()	
	for windowName,v in pairs(QuickStats.InMovement) do
		WindowSetMoving(windowName, false)		
		QuickStats.Save(windowName)
		QuickStats.InMovement[windowName] = nil
	end
	
end

QuickStats.InMovement = {}
function QuickStats.FindQuickStatMovingBlock(CurWindow)
	local anchorPositions = SnapUtils.ComputeAnchorScreenPositions(CurWindow)
	for windowName,_ in pairs(SnapUtils.SnappableWindows) do
		if( windowName ~= CurWindow and string.find(windowName, "QuickStat") and not QuickStats.InMovement[windowName] and not WindowGetMoving(windowName) ) then          
			local comparePositions = SnapUtils.ComputeAnchorScreenPositions(windowName)            
            
			for index, snapPair in ipairs( SnapUtils.SNAP_PAIRS )
			do
				local dist = SnapUtils.GetAnchorDistance( anchorPositions, snapPair[1], comparePositions, snapPair[2] )
               
				-- If the distance between the anchors is within the snap threshold, save the value
				if( (dist <= 5) and (dist < 6) and WindowGetShowing(windowName) )
				then
					
					WindowSetMoving(windowName, true)
					QuickStats.InMovement[windowName] = true
					QuickStats.FindQuickStatMovingBlock(windowName)
				end
		   end
		end
	end
end


function QuickStats.Context()
	local this = WindowGetParent(SystemData.ActiveWindow.name)
	local lab = QuickStats.Labels[WindowGetId(this)]

	if not lab then
		return
	end	

	if lab.locked then
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1111696),0,"lock",this ,false)
	else
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1111697),0,"lock",this ,false)
	end
	
	ContextMenu.CreateLuaContextMenuItemWithString(L" ",0,"",ni ,false)
	
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155391),0,"ShowIcon",this ,lab.icon)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155392),0,"ShowFrame",this ,lab.frame)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155393),0,"ShowName",this ,lab.name)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155394),0,"ShowCap",this ,lab.cap)
	
	if lab.objectType then
		ContextMenu.CreateLuaContextMenuItemWithString(ReplaceTokens(GetStringFromTid(1155478), {towstring(lab.minQuantity)}),0,"amtWarning",this ,false)
	else
		local k = tostring(WindowData.PlayerStatsDataCSV[lab.attribute].name)
		if (k ~= "Weight") then
			ContextMenu.CreateLuaContextMenuItemWithString(ReplaceTokens(GetStringFromTid(1155478), {towstring(lab.minQuantity)}),0,"amtWarning",this ,false)
		end
	end
	
	ContextMenu.CreateLuaContextMenuItemWithString(L" ",0,"",ni ,false)
	
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155395),0,"BGColor",this ,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155396),0,"FrameColor",this ,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155397),0,"NameColor",this ,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155398),0,"ValueColor",this ,false)
	
	ContextMenu.CreateLuaContextMenuItemWithString(L" ",0,"",ni ,false)
	
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155399),0,"Destroy",this ,false)
	
	ContextMenu.ActivateLuaContextMenu(QuickStats.ContextMenuCallback)
end

function QuickStats.ContextMenuCallback(returnCode, label)
	local lab = QuickStats.Labels[WindowGetId(label)]
	
	if ( returnCode=="lock" ) then
		lab.locked = not lab.locked
	elseif ( returnCode=="ShowIcon" ) then
		lab.icon = not lab.icon
	elseif ( returnCode=="ShowFrame" ) then
		lab.frame = not lab.frame
	elseif ( returnCode=="ShowName" ) then
		lab.name = not lab.name
	elseif ( returnCode=="ShowCap" ) then
		lab.cap = not lab.cap
	elseif ( returnCode=="amtWarning" ) then
		local rdata = {title=GetStringFromTid(1155400), subtitle=GetStringFromTid(1155401), callfunction=QuickStats.AmountSettings, id=WindowGetId(label)}
		RenameWindow.Create(rdata)
	elseif ( returnCode=="Destroy" ) then
		local okayButton = { textTid=UO_StandardDialog.TID_OKAY, callback=function() QuickStats.Destroy(label) end }
        local cancelButton = { textTid=UO_StandardDialog.TID_CANCEL }
		local DestroyConfirmWindow = 
		{
		    windowName = label,
			title = GetStringFromTid(1155399),
			body = GetStringFromTid(1155390),
			buttons = { okayButton, cancelButton }
		}
			
		UO_StandardDialog.CreateDialog(DestroyConfirmWindow)
	elseif ( string.find(returnCode, "Color") ) then	
		
		QuickStats.PickColor(string.gsub(returnCode, "Color", ""), label)
	end
	QuickStats.Save(label)
	QuickStats.UpdateLabel(label)
end

function QuickStats.AmountSettings(id, amount)
	if not tonumber(amount) then
		return
	else
		local lab = QuickStats.Labels[id]
		local label = "QuickStat_" .. id

		if not lab then
			return
		end

		lab.minQuantity = tonumber(amount)
		LabelSetTextColor(label.."AttributeValue", lab.valueTextColor.r,lab.valueTextColor.g,lab.valueTextColor.b)
		WindowStopAlphaAnimation(label.."AttributeValue")
		
		LabelSetTextColor(label.."AttributeName", lab.nameTextColor.r,lab.nameTextColor.g,lab.nameTextColor.b)
		WindowStopAlphaAnimation(label.."AttributeName")
		
	end
	QuickStats.Save("QuickStat_" .. id)
end

function QuickStats.Destroy(windowname)
	QuickStats.DeleteSettings(windowname)
	SnapUtils.SnappableWindows[windowname] = nil	
end

function QuickStats.PickColor(color, windowname)
	QuickStats.PickingColor = {windowname, color}
	local defaultColors = {
		0, --HUE_NONE 
		34, --HUE_RED
		53, --HUE_YELLOW
		63, --HUE_GREEN
		89, --HUE_BLUE
		119, --HUE_PURPLE
		144, --HUE_ORANGE
		368, --HUE_GREEN_2
		946, --HUE_GREY
		}
		local hueTable = {}
		for idx, hue in pairs(defaultColors) do
			for i=0,8 do
				hueTable[(idx-1)*10+i+1] = hue+i
			end
		end
		local Brightness = 1
		CreateWindowFromTemplate( "ColorPicker", "ColorPickerWindowTemplate", "Root" )
		WindowSetLayer( "ColorPicker", Window.Layers.SECONDARY	)
		ColorPickerWindow.SetNumColorsPerRow(9)
		ColorPickerWindow.SetSwatchSize(30)
		ColorPickerWindow.SetWindowPadding(4,4)
		ColorPickerWindow.SetFrameEnabled(true)
		ColorPickerWindow.SetCloseButtonEnabled(true)
		ColorPickerWindow.SetColorTable(hueTable,"ColorPicker")
		ColorPickerWindow.DrawColorTable("ColorPicker")
		ColorPickerWindow.SetAfterColorSelectionFunction(QuickStats.ColorPicked)
		local w, h = WindowGetDimensions("ColorPicker")
		WindowAddAnchor( "ColorPicker", "center", "Root", "center", 0, 0)
		ColorPickerWindow.SetFrameEnabled(false)
		WindowSetShowing( "ColorPicker", true )
		ColorPickerWindow.SelectColor("ColorPicker", 1)
end

function QuickStats.ColorPicked()
		local huePicked = ColorPickerWindow.colorSelected["ColorPicker"]
		local color = {}
		color.r, color.g, color.b, color.a = HueRGBAValue(huePicked)
		--Debug.Print("R: "..color.r.." G: "..color.g.." B: "..color.b.." A: "..color.a)

		local lab = QuickStats.Labels[WindowGetId(QuickStats.PickingColor[1])]

		if not lab then
			DestroyWindow("ColorPicker")
			return
		end

		if QuickStats.PickingColor[2] == "BG" then
			lab.BGColor = color
		elseif QuickStats.PickingColor[2] == "Frame" then
			lab.frameColor = color
		elseif QuickStats.PickingColor[2] == "Name" then
			lab.nameTextColor = color
		elseif QuickStats.PickingColor[2] == "Value" then
			lab.valueTextColor = color		
		end									 
		QuickStats.UpdateLabel(QuickStats.PickingColor[1])
		QuickStats.Save(QuickStats.PickingColor[1])			 
		DestroyWindow("ColorPicker")		 
end