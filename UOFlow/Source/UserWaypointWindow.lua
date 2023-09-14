----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

UserWaypointWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

UserWaypointWindow.TID = { Okay = 3000093, Cancel=1006045, CreateWaypoint=1079482, EditWaypoint=1079483,
					     Create=1077830, DeleteWaypoint=1079484, SelectAFacet=1079512, Type=1078603,
					     WaypointName=1079514, Coordinates=1079515, X=1112100, Y=1112101,
					     SelectAnIcon=1079519, MissingWaypointNameError=1079520, InvalidRangeCoordError=1079521,
					     Lat=1080540, Long=1080541, ViewWaypoint=1079571, East=1075387, West=1075390,
					     North=1075389, South=1075386}

UserWaypointWindow.Params = nil
UserWaypointWindow.XYcoords = false


UserWaypointWindow.Icons ={
[1] ={ id =100022, name=L"Custom"},
[2] ={ id =100000, name=L"Danger"},
[3] ={ id =100042, name=L"City"},
[4] ={ id =100045, name=L"Dungeon"},
[5] ={ id =100043, name=L"Bones"},
[6] ={ id =100010, name=L"Yellow Dot"},
[7] ={ id =100012, name=L"Healer"},
[8] ={ id =100053, name=L"Moongate"},
[9] ={ id =100018, name=L"Cross Weapons"},
[10] ={ id =100059, name=L"Shop"},
[11] ={ id =100060, name=L"Shrine"},
[12] ={ id =100030, name=L"Flag"},
[13] ={ id =100033, name=L"Alchemy"},
[14] ={ id =100034, name=L"Baker"},
[15] ={ id =100035, name=L"Bank"},
[16] ={ id =100036, name=L"Barber"},
[17] ={ id =100037, name=L"Bard"},
[18] ={ id =100038, name=L"Blacksmith"},
[19] ={ id =100039, name=L"Bowyer"},
[20] ={ id =100040, name=L"Butcher"},
[21] ={ id =100041, name=L"Carpenter"},
[22] ={ id =100046, name=L"Fletcher"},
[23] ={ id =100047, name=L"Guild"},
[24] ={ id =100048, name=L"Healer Shop"},
[25] ={ id =100049, name=L"Inn"},
[26] ={ id =100050, name=L"Jeweler"},
[27] ={ id =100051, name=L"Landmark"},
[28] ={ id =100052, name=L"Mage"},
[29] ={ id =100054, name=L"Painter"},
[30] ={ id =100056, name=L"Provisioner"},
[31] ={ id =100057, name=L"Reagents"},
[32] ={ id =100058, name=L"Shipwright"},
[33] ={ id =100061, name=GetStringFromTid(1154997)},
[34] ={ id =100062, name=L"Tailor"},
[35] ={ id =100063, name=L"Tavern"},
[36] ={ id =100064, name=L"Theater"},
[37] ={ id =100065, name=L"Tinker"},
[38] ={ id =100083, name=L"Black Pin"},
[39] ={ id =100084, name=L"Blue Pin"},
[40] ={ id =100085, name=L"Gold Skull Pin"},
[41] ={ id =100086, name=L"Green Pin"},
[42] ={ id =100087, name=L"Pink Pin"},
[43] ={ id =100088, name=L"Purple Pin"},
[44] ={ id =100089, name=L"Red Pin"},
[45] ={ id =100090, name=L"Yellow Pin"},
[46] ={ id =100106, name=L"Boat"},
[47] ={ id =100107, name=L"Cemetery"},
[48] ={ id =100108, name=L"Customs"},
[49] ={ id =100109, name=L"Dock"},
[50] ={ id =100110, name=L"Eye"},
[51] ={ id =100111, name=L"Gate"},
[52] ={ id =100112, name=L"Leather"},
[53] ={ id =100113, name=L"Mark"},
[54] ={ id =100114, name=L"Party"},
[55] ={ id =100115, name=L"Pillar"},
[56] ={ id =100116, name=L"Sink"},
[57] ={ id =100117, name=L"Stairs"},
[58] ={ id =100118, name=L"Target"},
[59] ={ id =100119, name=L"Teleporter"},
[60] ={ id =100120, name=L"Waves"},
[61] ={ id =100121, name=L"X"},
}

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function UserWaypointWindow.IconScaleUp()
    local scale = WindowGetScale("UserWaypointWindowTypeIcon")
    scale = scale + 0.1
    if (scale > 2) then
		scale = 2
	end
    WindowSetScale("UserWaypointWindowTypeIcon", scale)

end

function UserWaypointWindow.ScaleUpOnMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1155430))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function UserWaypointWindow.IconScaleDown()
    local scale = WindowGetScale("UserWaypointWindowTypeIcon")
    scale = scale - 0.1
    if (scale < 0.2) then
		scale = 0.2
	end
    WindowSetScale("UserWaypointWindowTypeIcon", scale)

end

function UserWaypointWindow.ScaleDownOnMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1155431))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function UserWaypointWindow.Initialize()
	RegisterWindowData(WindowData.WaypointDisplay.Type,0)

	LabelSetText("UserWaypointWindowNamePrompt", GetStringFromTid(UserWaypointWindow.TID.WaypointName))
	LabelSetText("UserWaypointWindowTypePrompt", GetStringFromTid(UserWaypointWindow.TID.Type))
    LabelSetText("UserWaypointWindowFacetPrompt", GetStringFromTid(UserWaypointWindow.TID.SelectAFacet))
    
	LabelSetText("UserWaypointWindowLatPrompt", GetStringFromTid(UserWaypointWindow.TID.Lat))
	LabelSetText("UserWaypointWindowLongPrompt", GetStringFromTid(UserWaypointWindow.TID.Long))
	
	LabelSetText("UserWaypointWindowXPrompt", GetStringFromTid(UserWaypointWindow.TID.X))
	LabelSetText("UserWaypointWindowYPrompt", GetStringFromTid(UserWaypointWindow.TID.Y))
	
	-- Set up Latitude direction combo box
	ComboBoxAddMenuItem( "UserWaypointWindowLatDirCombo", GetStringFromTid(UserWaypointWindow.TID.North) )
	ComboBoxAddMenuItem( "UserWaypointWindowLatDirCombo", GetStringFromTid(UserWaypointWindow.TID.South) )
	
	-- Set up Longitude direction combo box
	ComboBoxAddMenuItem( "UserWaypointWindowLongDirCombo", GetStringFromTid(UserWaypointWindow.TID.West) )
	ComboBoxAddMenuItem( "UserWaypointWindowLongDirCombo", GetStringFromTid(UserWaypointWindow.TID.East) )
	
	ButtonSetText("UserWaypointWindowOKButton",  GetStringFromTid(UserWaypointWindow.TID.Okay)) 
	ButtonSetText("UserWaypointWindowCancelButton",  GetStringFromTid(UserWaypointWindow.TID.Cancel))

    -- These are not editable yet
--	WindowSetShowing("UserWaypointWindowTypeText",false)
	WindowSetShowing("UserWaypointWindowFacetText",false)
	
	tabIndex = 3
end

function UserWaypointWindow.Shutdown()
	UnregisterWindowData(WindowData.WaypointDisplay.Type,0)
end

function UserWaypointWindow.InitializeCreateWaypointData(params)
	WindowSetScale("UserWaypointWindowTypeIcon", 1)
	-- DEFAULT VALUES FOR NEW CUSTOM WAYPOINTS
	params.type = MapCommon.WaypointCustomType
	
	UserWaypointWindow.Params = params
	
	WindowUtils.SetWindowTitle("UserWaypointWindow", GetStringFromTid(UserWaypointWindow.TID.CreateWaypoint))
	WindowSetShowing("UserWaypointWindowCancelButton", true)
	
	TextEditBoxSetText("UserWaypointWindowNameTextEditBox",L"")
	--LabelSetText("UserWaypointWindowTypeLabel",WindowData.WaypointDisplay.typeNames[params.type])
	--- ICONS
	ComboBoxClearMenuItems("UserWaypointWindowTypeLabel")
	local n = table.getn(UserWaypointWindow.Icons)
	for i = 1, n do
		ComboBoxAddMenuItem( "UserWaypointWindowTypeLabel", UserWaypointWindow.Icons[i].name )
	end
	WindowSetShowing("UserWaypointWindowTypeScaleUp", true)
	WindowSetShowing("UserWaypointWindowTypeScaleDown", true)
	
	local iconTexture, x, y = GetIconData(100022)
    local iconWidth, iconHeight = UOGetTextureSize("icon"..100022)

    WindowSetDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
    DynamicImageSetTextureDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
    DynamicImageSetTexture("UserWaypointWindowTypeIcon", iconTexture, x, y)
    
	ComboBoxSetSelectedMenuItem( "UserWaypointWindowTypeLabel", 1)
	
	
	UserWaypointWindow.XYcoords = false

	UserWaypointWindow.UpdateCoordInfo(params.x, params.y, params.facetId)

	
	WindowSetShowing("UserWaypointWindowNameText",true)
	WindowSetShowing("UserWaypointWindowNameLabel",false)
	
	-- Hide display-only windows
	WindowSetShowing("UserWaypointWindowLatLabel",false)
	WindowSetShowing("UserWaypointWindowLongLabel",false)
	WindowSetShowing("UserWaypointWindowXLabel",false)
	WindowSetShowing("UserWaypointWindowYLabel",false)
	
	-- Show input-related windows
	WindowSetShowing("UserWaypointWindowLatText",true)
	WindowSetShowing("UserWaypointWindowLongText",true)
	WindowSetShowing("UserWaypointWindowXText",true)
	WindowSetShowing("UserWaypointWindowYText",true)
	
	local area = UOGetRadarArea()

	local facet = UOGetRadarFacet()
--Debug.Print("F: " ..facet .. " A: " .. area)
	if (area > 0 and  ((facet == 0 and area ~= MapCommon.sextantFeluccaLostLands) or (facet == 1 and area ~= MapCommon.sextantTrammelLostLands) or facet > 1) ) then
		UserWaypointWindow.XYcoords = true
		WindowSetShowing("UserWaypointWindowToggleCoordButton", false)

		-- Show latitude/longitude windows first
		WindowSetShowing("UserWaypointWindowLat",false)
		WindowSetShowing("UserWaypointWindowLong",false)
		WindowSetShowing("UserWaypointWindowX",true)
		WindowSetShowing("UserWaypointWindowY",true)
		
		WindowSetShowing("UserWaypointWindowLatDirCombo",false)
		WindowSetShowing("UserWaypointWindowLongDirCombo",false)
	else
		UserWaypointWindow.XYcoords = false
		WindowSetShowing("UserWaypointWindowToggleCoordButton", true)
		UserWaypointWindow.UpdateCoordInfo(params.x, params.y, params.facetId)
		-- Show latitude/longitude windows first
		WindowSetShowing("UserWaypointWindowLat",true)
		WindowSetShowing("UserWaypointWindowLong",true)
		WindowSetShowing("UserWaypointWindowX",false)
		WindowSetShowing("UserWaypointWindowY",false)

		WindowSetShowing("UserWaypointWindowLatDirCombo",true)
		WindowSetShowing("UserWaypointWindowLongDirCombo",true)
	end
	
    WindowSetShowing("UserWaypointWindow", true)
    WindowAssignFocus("UserWaypointWindowNameTextEditBox", true)	
end

local tabIndex = 3
function UserWaypointWindow.OnKeyTab()

	if (tabIndex < 3) then
		tabIndex = tabIndex +1
	else
		tabIndex = 1
	end
	if(tabIndex == 3) then
		WindowAssignFocus("UserWaypointWindowNameTextEditBox",true)
	elseif(tabIndex == 1) then

		if (not UserWaypointWindow.XYcoords) then
			WindowAssignFocus("UserWaypointWindowLatTextEditBox",true)
		else
			WindowAssignFocus("UserWaypointWindowXTextEditBox",true)
		end
	elseif(tabIndex == 2) then
		if (not UserWaypointWindow.XYcoords) then
			WindowAssignFocus("UserWaypointWindowLongTextEditBox",true)
			
		else
			WindowAssignFocus("UserWaypointWindowYTextEditBox",true)
			
		end
	end
end

function UserWaypointWindow.InitializeViewWaypointData(params)
	WindowSetScale("UserWaypointWindowTypeIcon", 1)
    UserWaypointWindow.Params = params

	WindowUtils.SetWindowTitle("UserWaypointWindow",  GetStringFromTid(UserWaypointWindow.TID.ViewWaypoint))
	
	WindowSetShowing("UserWaypointWindowCancelButton", false)
	
	LabelSetText("UserWaypointWindowNameLabel",params.name)
	--LabelSetText("UserWaypointWindowTypeLabel",WindowData.WaypointDisplay.typeNames[params.type])
	
	--- ICONS
	ComboBoxClearMenuItems("UserWaypointWindowTypeLabel")
	local n = table.getn(UserWaypointWindow.Icons)
	for i = 1, n do
		ComboBoxAddMenuItem( "UserWaypointWindowTypeLabel", UserWaypointWindow.Icons[i].name )
	end

	local selection = params.type
	--Debug.Print(params.type)
	if (params.type == 11) then
		selection = 11
	elseif (params.type == 10) then
		selection = 4
	elseif (params.type == 9) then
		selection = 3
	elseif (params.type == 12) then
		selection = 8
	elseif (params.type == 7) then
		selection = 2
	elseif (params.type == 2) then
		selection = 9
	end
	ComboBoxSetSelectedMenuItem( "UserWaypointWindowTypeLabel", selection)
	
	
	local iconId = UserWaypointWindow.Icons[selection].id
	local iconTexture, x, y = GetIconData(iconId)
    local iconWidth, iconHeight = UOGetTextureSize("icon"..iconId)
    local iconScale = MapCommon.GetWaypointScale(displayMode)
	if params.scale then
		iconScale = params.scale
	end
	WindowSetShowing("UserWaypointWindowTypeScaleUp", false)
	WindowSetShowing("UserWaypointWindowTypeScaleDown", false)
    WindowSetDimensions("UserWaypointWindowTypeIcon", iconWidth* iconScale, iconHeight* iconScale)
    DynamicImageSetTextureDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
    DynamicImageSetTexture("UserWaypointWindowTypeIcon", iconTexture, x, y)
    
	
	
	
	
	WindowSetShowing("UserWaypointWindowNameText",false)
	WindowSetShowing("UserWaypointWindowNameLabel",true)
	
	-- Show display-only windows
	WindowSetShowing("UserWaypointWindowLatLabel",true)
	WindowSetShowing("UserWaypointWindowLongLabel",true)
	WindowSetShowing("UserWaypointWindowXLabel",true)
	WindowSetShowing("UserWaypointWindowYLabel",true)
	
	-- Hide input-related windows
	WindowSetShowing("UserWaypointWindowLatText",false)
	WindowSetShowing("UserWaypointWindowLongText",false)
	WindowSetShowing("UserWaypointWindowLatDirCombo",false)
	WindowSetShowing("UserWaypointWindowLongDirCombo",false)
	WindowSetShowing("UserWaypointWindowXText",false)
	WindowSetShowing("UserWaypointWindowYText",false)
	
	local area = UOGetRadarArea()
	if (area > 0 and  ((facet == 0 and area ~= MapCommon.sextantFeluccaLostLands) or (facet == 1 and area ~= MapCommon.sextantTrammelLostLands) or facet > 1) ) then
		UserWaypointWindow.XYcoords = true
		WindowSetShowing("UserWaypointWindowToggleCoordButton", false)
		-- Show latitude/longitude windows first
		WindowSetShowing("UserWaypointWindowLat",false)
		WindowSetShowing("UserWaypointWindowLong",false)
		WindowSetShowing("UserWaypointWindowX",true)
		WindowSetShowing("UserWaypointWindowY",true)
		
	else
		UserWaypointWindow.XYcoords = false
		WindowSetShowing("UserWaypointWindowToggleCoordButton", true)
		UserWaypointWindow.UpdateCoordInfo(params.x, params.y, params.facetId)
		-- Show latitude/longitude windows first
		WindowSetShowing("UserWaypointWindowLat",true)
		WindowSetShowing("UserWaypointWindowLong",true)
		WindowSetShowing("UserWaypointWindowX",false)
		WindowSetShowing("UserWaypointWindowY",false)
	end
	
	
	
    WindowSetShowing("UserWaypointWindow", true)	
end

function UserWaypointWindow.ToggleCoord()
	if (UserWaypointWindow.XYcoords == false) then
		-- Show X/Y windows
		WindowSetShowing("UserWaypointWindowLat",false)
		WindowSetShowing("UserWaypointWindowLong",false)
		WindowSetShowing("UserWaypointWindowX",true)
		WindowSetShowing("UserWaypointWindowY",true)
		
		-- If waypoint is being created
		if (UserWaypointWindow.Params.type == MapCommon.WaypointCustomType) then
			-- Retrieve latitude/longitude values
			local area = UOGetRadarArea()
			local latVal = tonumber(TextEditBoxGetText("UserWaypointWindowLatTextEditBox"))

			local longVal = tonumber(TextEditBoxGetText("UserWaypointWindowLongTextEditBox"))
			
			WindowSetTabOrder( "UserWaypointWindowXTextEditBox", 0 )
			WindowSetTabOrder( "UserWaypointWindowYTextEditBox", 0 )
		
			WindowSetTabOrder( "UserWaypointWindowLatTextEditBox", 2 )
			WindowSetTabOrder( "UserWaypointWindowLongTextEditBox", 3 )
		
			local latDir = L"N"
			local longDir = L"W"
			if (ComboBoxGetSelectedMenuItem("UserWaypointWindowLatDirCombo") == 2) then
				latDir = L"S"
			end
			if (ComboBoxGetSelectedMenuItem("UserWaypointWindowLongDirCombo") == 2) then
				longDir = L"E"
			end
			
			-- Convert to latitude/longitude to x/y
			
			UserWaypointWindow.Params.x, UserWaypointWindow.Params.y = MapCommon.ConvertToXYMinutes(latVal, longVal, latDir, longDir, UserWaypointWindow.Params.facetId, area)
			
			-- Update input boxes with new values
			UserWaypointWindow.UpdateCoordInfo(UserWaypointWindow.Params.x, UserWaypointWindow.Params.y, UserWaypointWindow.Params.facetId)
			
			-- Hide N/S and W/E comboboxes
			WindowSetShowing("UserWaypointWindowLatDirCombo",false)
			WindowSetShowing("UserWaypointWindowLongDirCombo",false)
		end
		
		UserWaypointWindow.XYcoords = true
	else
		-- Show Latitude/Longitude windows
		WindowSetShowing("UserWaypointWindowLat",true)
		WindowSetShowing("UserWaypointWindowLong",true)
		WindowSetShowing("UserWaypointWindowX",false)
		WindowSetShowing("UserWaypointWindowY",false)
		
		WindowSetTabOrder( "UserWaypointWindowLatTextEditBox", 0 )
		WindowSetTabOrder( "UserWaypointWindowLongTextEditBox", 0 )
			
		WindowSetTabOrder( "UserWaypointWindowXTextEditBox", 2 )
		WindowSetTabOrder( "UserWaypointWindowYTextEditBox", 3 )
		
		-- If waypoint is being created
		if (UserWaypointWindow.Params.type == MapCommon.WaypointCustomType) then
			-- Retrieve x/y values
			UserWaypointWindow.Params.x = tonumber(TextEditBoxGetText("UserWaypointWindowXTextEditBox"))
			UserWaypointWindow.Params.y = tonumber(TextEditBoxGetText("UserWaypointWindowYTextEditBox"))
			
			-- Update the input boxes with new values
			UserWaypointWindow.UpdateCoordInfo(UserWaypointWindow.Params.x, UserWaypointWindow.Params.y, UserWaypointWindow.Params.facetId)
			
			-- Show N/S and W/E comboboxes
			WindowSetShowing("UserWaypointWindowLatDirCombo",true)
			WindowSetShowing("UserWaypointWindowLongDirCombo",true)
		end
		
		UserWaypointWindow.XYcoords = false
	end
end

function UserWaypointWindow.ToggleCoordMouseOver()
	local buttonName = "UserWaypointWindowToggleCoordButton"
	local text = GetStringFromTid(1112099)
	Tooltips.CreateTextOnlyTooltip(buttonName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function UserWaypointWindow.UpdateCoordInfo(x, y, facet)
	local area = UOGetRadarArea()
	LabelSetText("UserWaypointWindowFacetLabel",GetStringFromTid(UORadarGetFacetLabel(facet)) .. L" - " .. GetStringFromTid(UORadarGetAreaLabel(facet, area)))

	local latStr, longStr, latDir, longDir = MapCommon.GetSextantLocationStrings(x, y, facet)
	
	-- If waypoint is being created
	if(UserWaypointWindow.Params.type == MapCommon.WaypointCustomType) then
		TextEditBoxSetText("UserWaypointWindowLatTextEditBox", latStr)
		TextEditBoxSetText("UserWaypointWindowLongTextEditBox", longStr)
		TextEditBoxSetText("UserWaypointWindowXTextEditBox", StringToWString(string.format("%.0f",x)) )
		TextEditBoxSetText("UserWaypointWindowYTextEditBox", StringToWString(string.format("%.0f",y)) )
		
		if(latDir == L"N") then
			ComboBoxSetSelectedMenuItem( "UserWaypointWindowLatDirCombo", 1)
		else
			ComboBoxSetSelectedMenuItem( "UserWaypointWindowLatDirCombo", 2)
		end
		
		if(longDir == L"W") then
			ComboBoxSetSelectedMenuItem( "UserWaypointWindowLongDirCombo", 1)
		else
			ComboBoxSetSelectedMenuItem( "UserWaypointWindowLongDirCombo", 2)
		end
	else
		LabelSetText("UserWaypointWindowLatLabel",latStr..L"'"..latDir)
		LabelSetText("UserWaypointWindowLongLabel",longStr..L"'"..longDir)
		LabelSetText("UserWaypointWindowXLabel", StringToWString(string.format("%.0f",x)) )
		LabelSetText("UserWaypointWindowYLabel", StringToWString(string.format("%.0f",y)) )
	end
end

function UserWaypointWindow.OnOkay()
	-- If waypoint is being created
	
    if( UserWaypointWindow.Params.type == MapCommon.WaypointCustomType ) then
		-- Retrieve waypoint name
        local name = TextEditBoxGetText("UserWaypointWindowNameTextEditBox")
        if( name == L"" ) then
            return
        end
        local area = 0
        if (UserWaypointWindow.XYcoords == true) then
			-- Retreive x/y coords
			local x = TextEditBoxGetText("UserWaypointWindowXTextEditBox")
			local y = TextEditBoxGetText("UserWaypointWindowYTextEditBox")
			
			if (x == L"" or y == L"") then
				return
			end
			
			UserWaypointWindow.Params.x = tonumber(x)
			UserWaypointWindow.Params.y = tonumber(y)
			area = UOGetRadarArea()
        else
			-- Retrieve latitude/longitude coords
			local latVal = TextEditBoxGetText("UserWaypointWindowLatTextEditBox")
			local longVal = TextEditBoxGetText("UserWaypointWindowLongTextEditBox")
			if (latVal == L"" or longVal == L"") then
				return
			end
			local latDir = L"N"
			local longDir = L"W"
			if (ComboBoxGetSelectedMenuItem("UserWaypointWindowLatDirCombo") == 2) then
				latDir = L"S"
			end
			if (ComboBoxGetSelectedMenuItem("UserWaypointWindowLongDirCombo") == 2) then
				longDir = L"E"
			end
			area = UOGetRadarArea()

			-- Convert to x/y coords
			UserWaypointWindow.Params.x, UserWaypointWindow.Params.y = MapCommon.ConvertToXYMinutes(tonumber(latVal), tonumber(longVal), latDir, longDir, UserWaypointWindow.Params.facetId, area)
        end
        local curSel = ComboBoxGetSelectedMenuItem( "UserWaypointWindowTypeLabel" )

		local iconId = StringToWString(tostring(UserWaypointWindow.Icons[curSel].id))
		local iconScale = WindowGetScale("UserWaypointWindowTypeIcon")
		iconScale = tonumber(string.sub(tostring(iconScale),1 , 4))
		local nameAdd = L""
		if (UserWaypointWindow.Params.facetId == 4 and area > 0) then
			nameAdd = L"_DUNG_"
		end
		if (UserWaypointWindow.Params.facetId == 5 and area == 1) then
			nameAdd = L"_ABYSS_"
		end
		if (UserWaypointWindow.Params.facetId == 5 and (area == 2 or area == 7)) then
			UserWaypointWindow.Params.facetId = 0
		end
		
        UOCreateUserWaypoint( UserWaypointWindow.Params.type, UserWaypointWindow.Params.x, UserWaypointWindow.Params.y, UserWaypointWindow.Params.facetId, name .. L"_ICON_" .. iconId .. L"_SCALE_" .. iconScale .. nameAdd )
        MapCommon.ForcedUpdate = true
		MapCommon.UpdateWaypoints(MapCommon.ActiveView)
    end
    
    WindowSetShowing("UserWaypointWindow", false)	
end

function UserWaypointWindow.OnKeyCancel()
	MainMenuWindow.notnow = true
	UserWaypointWindow.OnCancel()
end

function UserWaypointWindow.OnCancel()
    WindowSetShowing("UserWaypointWindow", false)
end

function UserWaypointWindow.OnSelChanged()
	local curSel = ComboBoxGetSelectedMenuItem( "UserWaypointWindowTypeLabel" )

	local iconId = UserWaypointWindow.Icons[curSel].id
	if (type(iconId) == "number") then
		local iconTexture, x, y = GetIconData(iconId)
		local iconWidth, iconHeight = UOGetTextureSize("icon"..iconId)
		WindowSetDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
		DynamicImageSetTextureDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
		DynamicImageSetTexture("UserWaypointWindowTypeIcon", iconTexture, x, y)
	else
		local iconWidth, iconHeight = UOGetTextureSize(iconId)
		WindowSetDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
		DynamicImageSetTextureDimensions("UserWaypointWindowTypeIcon", iconWidth, iconHeight)
		DynamicImageSetTexture("UserWaypointWindowTypeIcon", iconId, 0, 0)
	end
end