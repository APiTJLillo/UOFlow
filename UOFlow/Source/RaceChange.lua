----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

RaceChangeWindow = {}

RaceChangeWindow.TID = {	Creation=3000109 , Race=1077827 , Profession=1077828 , Appearance=1077829 , Create=1077830 ,
							MALE=1077831 ,FEMALE=1077832, STRENGTH=1077833 , DEXTERITY=1077834 , INTELLIGENCE=1077835 ,
							Name=1037013 , Gender=3000120, Strength=1027996 , Dexterity=1061147 , Intelligence=1061148 ,
							notAva=1077836, descrip=1077837, enterName=1077838, Customize=1011355, Custom=1077246,
							CustomProfessionText=1061226, Defaults=3001015, Shirt=1011359, ShirtColor=3000440, Pants=1015279,
							PantsColor=3000441, HairStyle=3000121, HairColor=3000184, FacialHairStyle=3000122,
							HornStyle=1112309, HornColor=1112322, FacialHornStyle=1112511, FacialHornColor=1112512,
							FacialHairColor=3000446, SelectFace=3000438, SkinTone=3000183, Shoes=1011390, Appearance=1077829,
							TimeoutWarningMessage=3000005, TimeoutWarning=1078112, ShoeColor=1078150, Stats=3010049, Skills=3000084
						}

RaceChangeWindow.WindowName = 0

RCWskinColor		= 0
RCWhairStyle		= 0
RCWhairColor		= 0
RCWfacialHairStyle	= 0
RCWfacialHairColor	= 0

RCWrace				= 0
RCWgender			= 0

local WindowList = {}

function RaceChangeWindow.Initialize()
	RaceChangeWindow.WindowName = SystemData.ActiveWindow.name
	local WindowName = RaceChangeWindow.WindowName
		
	WindowRegisterEventHandler( "Root",  SystemData.Events.CHARACTER_TOKEN_PAPERDOLL_UPDATED, "RaceChangeWindow.UpdatePaperdollTextureSize")

	--Debug.PrintToDebugConsole(L"RaceChangeWindow.Initialize started")
	--Debug.PrintToDebugConsole(L"Gender= "..StringToWString(tostring( WindowData.RaceChange.Gender)))
	--Debug.PrintToDebugConsole(L"Race= "..StringToWString(tostring( WindowData.RaceChange.Race)))
	--Debug.PrintToDebugConsole(L"win name= "..StringToWString(SystemData.ActiveWindow.name))
	
    ButtonSetText (WindowName.."OkButton", L"Ok")
    
    --LabelSetText( WindowName.."Text", GetStringFromTid(RaceChangeWindow.TID.Appearance))
    LabelSetText( WindowName.."SkinLabel", GetStringFromTid(RaceChangeWindow.TID.SelectFace))
    LabelSetText( WindowName.."SkinColorLabel", GetStringFromTid(RaceChangeWindow.TID.SkinTone))

    UOBuildTableFromCSV ("Data/GameData/characterhues.csv", "CharacterHuesCSV")
    UOBuildTableFromCSV ("Data/GameData/characterfacestyles.csv", "CharacterFaceStylesCSV")
    UOBuildTableFromCSV ("Data/GameData/characterrace.csv", "RacesCSV")
    UOBuildTableFromCSV ("Data/GameData/elfhairhues.csv", "ElfHairHuesCSV")
    UOBuildTableFromCSV ("Data/GameData/elfskinhues.csv", "ElfSkinHuesCSV")
    UOBuildTableFromCSV ("Data/GameData/elffacestyles.csv", "ElfFaceStylesCSV")
    UOBuildTableFromCSV ("Data/GameData/gargoylehornhues.csv", "GargoyleHornHuesCSV")
    UOBuildTableFromCSV ("Data/GameData/gargoyleskinhues.csv", "GargoyleSkinHuesCSV")
    UOBuildTableFromCSV ("Data/GameData/gargoylefacestyles.csv", "GargoyleFaceStylesCSV")
    UOBuildTableFromCSV ("Data/GameData/femaleelfhairstyle.csv", "FemaleElfHairstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/femalegargoylehornstyle.csv", "FemaleGargoyleHornstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/femalehumanhairstyle.csv", "FemaleHumanHairstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/maleelfhairstyle.csv", "MaleElfHairstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/malegargoylehornstyle.csv", "MaleGargoyleHornstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/malegargoylefacialhornstyle.csv", "MaleGargoyleFacialHornstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/malehumanhairstyle.csv", "MaleHumanHairstylesCSV")
    UOBuildTableFromCSV ("Data/GameData/malehumanfacialhairstyle.csv", "MaleHumanFacialHairstylesCSV")

	RCWrace = WindowData.RaceChange.Race
	RCWgender = WindowData.RaceChange.Gender
	
	if (RCWrace == 1) then
		WindowUtils.SetWindowTitle (WindowName, GetStringFromTid (1079262)) --"Change Race To Human"
	elseif (RCWrace == 2) then
		WindowUtils.SetWindowTitle (WindowName, GetStringFromTid (1079444)) --"Change Race To Elf"	
	elseif (RCWrace == 3) then
		WindowUtils.SetWindowTitle (WindowName, GetStringFromTid (1015249)) --"Change Race To Gargoyle"	
	end	
	
	if (RCWrace == 1) then
		LabelSetText( WindowName.."HairLabel", GetStringFromTid(RaceChangeWindow.TID.HairStyle))
		LabelSetText( WindowName.."HairColorLabel", GetStringFromTid(RaceChangeWindow.TID.HairColor))
		LabelSetText( WindowName.."FacialHairLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHairStyle))
		LabelSetText( WindowName.."FacialHairColorLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHairColor ))
	
		-- SETUP DEFAULT HUMAN COLOR PICKER WINDOWS
		-- TO DO: GET HUES FROM RESPECTIVE CSV FILE !!!
		local colorPickerWindowName = nil
		local switch = false
		local colorTable = {}
		local startHue = nil
		local maxHue = nil
		local defaultHue = nil
		for key, colorPickerName in pairs({"Skin", "Hair", "FacialHair"}) do
			colorPickerWindowName = WindowName..colorPickerName.."ColorPicker"
			table.insert (WindowList, colorPickerWindowName)

			CreateWindowFromTemplate( colorPickerWindowName, "ColorPickerWindowTemplate", "Root" )
	        
			if (colorPickerName == "Skin") then
				startHue = 1002
				maxHue = 1057
				defaultHue =  1010
				RCWskinColor = defaultHue
			elseif (colorPickerName == "Hair") then
		 		startHue = 1102
		 		maxHue = 1148
		 		defaultHue = 1130
				RCWhairColor = defaultHue

			elseif (colorPickerName == "FacialHair") then
				startHue =  1102
				maxHue = 1148
				defaultHue =  1123
				RCWfacialHairColor = defaultHue
			end
			 
			colorTable = {} 
			
			local i = 1 
			for hue=startHue,maxHue do
				colorTable[i]= hue
				i = i + 1  
			end
			
			ColorPickerWindow.SetColorTable(colorTable, colorPickerWindowName)
			 		
			ColorPickerWindow.SetNumColorsPerRow(7)
	        
			ColorPickerWindow.DrawColorTable(colorPickerWindowName)
  			WindowClearAnchors (colorPickerWindowName)
			WindowAddAnchor( colorPickerWindowName, "bottom", WindowName..colorPickerName, "top", 0, 0)
			WindowSetShowing( colorPickerWindowName, false)
		end
    elseif (RCWrace == 2) then
		LabelSetText( WindowName.."HairLabel", GetStringFromTid(RaceChangeWindow.TID.HairStyle))
		LabelSetText( WindowName.."HairColorLabel", GetStringFromTid(RaceChangeWindow.TID.HairColor))
		LabelSetText( WindowName.."FacialHairLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHairStyle))
		LabelSetText( WindowName.."FacialHairColorLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHairColor ))
		
		-- CREATE ELF SKIN & HAIR COLOR PICKER WINDOWS
		for key, colorPickerName in pairs({"ElfSkin", "ElfHair"}) do
			colorPickerWindowName = WindowName..colorPickerName.."ColorPicker"

			CreateWindowFromTemplate( colorPickerWindowName, "ColorPickerWindowTemplate", "Root" )

			colorTable = {}

			if colorPickerName == "ElfSkin" then
				defaultHue =  1245
				RCWskinColor = defaultHue
				local numHues = CSVUtilities.getNumRows(WindowData.ElfSkinHuesCSV)

				for hueIndex = 1,numHues do
					colorTable[hueIndex] = WindowData.ElfSkinHuesCSV[hueIndex].ElfSkinHues
				end
			elseif colorPickerName == "ElfHair" then
				defaultHue =  52
				RCWhairColor = defaultHue
				local numHues = CSVUtilities.getNumRows(WindowData.ElfHairHuesCSV)
				for hueIndex = 1,numHues do
					if (WindowData.ElfHairHuesCSV[hueIndex].ElfHairHues) then
						colorTable[hueIndex] = WindowData.ElfHairHuesCSV[hueIndex].ElfHairHues
					end
				end
			end
			
			-- default these to 0 since they have to be set to something
			RCWfacialHairColor = 0
			RCWfacialHairStyle = 0
			
			ColorPickerWindow.SetColorTable(colorTable, colorPickerWindowName)

			ColorPickerWindow.SetNumColorsPerRow(7)
			ColorPickerWindow.DrawColorTable(colorPickerWindowName)

			ColorPickerWindow.SetHue(defaultHue, colorPickerWindowName)

  			WindowClearAnchors (colorPickerWindowName)
  			WindowAddAnchor( colorPickerWindowName, "bottomleft", WindowName.."Hair", "topleft", 30, 10)
			WindowSetShowing( colorPickerWindowName, false)
			
		end
    elseif (RCWrace == 3) then
		LabelSetText( WindowName.."HairLabel", GetStringFromTid(RaceChangeWindow.TID.HornStyle))
		LabelSetText( WindowName.."HairColorLabel", GetStringFromTid(RaceChangeWindow.TID.HornColor))
		LabelSetText( WindowName.."FacialHairLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHornStyle))
		LabelSetText( WindowName.."FacialHairColorLabel", GetStringFromTid(RaceChangeWindow.TID.FacialHornColor ))
		
		-- CREATE Gargoyle SKIN & HAIR COLOR PICKER WINDOWS
		for key, colorPickerName in pairs({"GargoyleSkin", "GargoyleHair", "GargoyleFacialHair"}) do
			colorPickerWindowName = WindowName..colorPickerName.."ColorPicker"

			CreateWindowFromTemplate( colorPickerWindowName, "ColorPickerWindowTemplate", "Root" )

			colorTable = {}

			if colorPickerName == "GargoyleSkin" then
				local numHues = CSVUtilities.getNumRows(WindowData.GargoyleSkinHuesCSV)
				for hueIndex = 1,numHues do
					colorTable[hueIndex] = WindowData.GargoyleSkinHuesCSV[hueIndex].GargoyleSkinHues
				end
				
				defaultHue = colorTable[1]
				RCWskinColor = defaultHue
			elseif colorPickerName == "GargoyleHair" then
				local numHues = CSVUtilities.getNumRows(WindowData.GargoyleHornHuesCSV)
				for hueIndex = 1,numHues do
					if (WindowData.GargoyleHornHuesCSV[hueIndex].GargoyleHornHues) then
						colorTable[hueIndex] = WindowData.GargoyleHornHuesCSV[hueIndex].GargoyleHornHues
					end
				end
				
				defaultHue = colorTable[1]
				RCWhairColor = defaultHue
			elseif (colorPickerName == "GargoyleFacialHair") then
				local numHues = CSVUtilities.getNumRows(WindowData.GargoyleHornHuesCSV)
				for hueIndex = 1,numHues do
					if (WindowData.GargoyleHornHuesCSV[hueIndex].GargoyleHornHues) then
						colorTable[hueIndex] = WindowData.GargoyleHornHuesCSV[hueIndex].GargoyleHornHues
					end
				end
				defaultHue = colorTable[1]
				RCWfacialHairColor = defaultHue
			end
			
			ColorPickerWindow.SetColorTable(colorTable, colorPickerWindowName)

			ColorPickerWindow.SetNumColorsPerRow(7)
			ColorPickerWindow.DrawColorTable(colorPickerWindowName)

			ColorPickerWindow.SetHue(defaultHue, colorPickerWindowName)

  			WindowClearAnchors (colorPickerWindowName)
  			WindowAddAnchor( colorPickerWindowName, "bottomleft", WindowName.."Hair", "topleft", 30, 10)
			WindowSetShowing( colorPickerWindowName, false)
		end
	end

	--  if you are currently human then show the elf model.  Gender stays the same
	-- race has been set by the server
	if (RCWrace == 1) then
		-- becoming a human				
		ColorPickerWindow.SetHue(RCWskinColor, WindowName.."SkinColorPicker")
		ColorPickerWindow.SetHue(RCWhairColor, WindowName.."HairColorPicker")

		if (RCWgender == 0) then -- male
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.MaleHumanHairstylesCSV)
			RCWhairStyle  = WindowData.MaleHumanHairstylesCSV[1].TileArtId
			RCWfacialHairStyles = RaceChangeWindow.createWearableTable(WindowData.MaleHumanFacialHairstylesCSV)
			RCWfacialHairStyle = 0
		else
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.FemaleHumanHairstylesCSV)
			RCWhairStyle  = WindowData.FemaleHumanHairstylesCSV[1].TileArtId
			RCWfacialHairStyle = 0	
			
			WindowSetShowing (WindowName.."FacialHairLabel", false)
			WindowSetShowing (WindowName.."FacialHairStyle", false)
			WindowSetShowing (WindowName.."FacialHairBackground", false)
			WindowSetShowing (WindowName.."FacialHairUpButton", false)
			WindowSetShowing (WindowName.."FacialHairDownButton", false)

			WindowSetShowing (WindowName.."FacialHairColor", false)
			WindowSetShowing (WindowName.."FacialHairColorLabel", false)
		end
	end
	
	if (RCWrace == 2) then 
		-- becoming elf
		ColorPickerWindow.SetHue(RCWskinColor, WindowName.."ElfSkinColorPicker")
		ColorPickerWindow.SetHue(RCWhairColor, WindowName.."ElfHairColorPicker")

		if (RCWgender == 0) then -- male
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.MaleElfHairstylesCSV)
			RCWhairStyle  = WindowData.MaleElfHairstylesCSV[1].TileArtId
			RCWfacialHairStyle  = 0
		else
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.FemaleElfHairstylesCSV)
			RCWhairStyle  = WindowData.FemaleElfHairstylesCSV[1].TileArtId
			RCWfacialHairStyle  = 0
		end

		-- don't show facial hair stuff for elvees
		WindowSetShowing (WindowName.."FacialHairLabel", false)
		WindowSetShowing (WindowName.."FacialHairStyle", false)
		WindowSetShowing (WindowName.."FacialHairBackground", false)
		WindowSetShowing (WindowName.."FacialHairUpButton", false)
		WindowSetShowing (WindowName.."FacialHairDownButton", false)

		WindowSetShowing (WindowName.."FacialHairColor", false)
		WindowSetShowing (WindowName.."FacialHairColorLabel", false)

	end
	
	if (RCWrace == 3) then 
		-- becoming Gargoyle				
		ColorPickerWindow.SetHue(RCWskinColor, WindowName.."GargoyleSkinColorPicker")
		ColorPickerWindow.SetHue(RCWhairColor, WindowName.."GargoyleHairColorPicker")

		if (RCWgender == 0) then -- male
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.MaleGargoyleHornstylesCSV)
			RCWhairStyle  = WindowData.MaleGargoyleHornstylesCSV[1].TileArtId
			RCWfacialHairStyles = RaceChangeWindow.createWearableTable(WindowData.MaleGargoyleFacialHornstylesCSV)
			RCWfacialHairStyle  = 0
		else
			RCWhairStyles = RaceChangeWindow.createWearableTable(WindowData.FemaleGargoyleHornstylesCSV)
			RCWhairStyle  = WindowData.FemaleGargoyleHornstylesCSV[1].TileArtId
			RCWfacialHairStyle  = 0
			
			WindowSetShowing (WindowName.."FacialHairLabel", false)
			WindowSetShowing (WindowName.."FacialHairStyle", false)
			WindowSetShowing (WindowName.."FacialHairBackground", false)
			WindowSetShowing (WindowName.."FacialHairUpButton", false)
			WindowSetShowing (WindowName.."FacialHairDownButton", false)

			WindowSetShowing (WindowName.."FacialHairColor", false)
			WindowSetShowing (WindowName.."FacialHairColorLabel", false)
		end
	end
	
	-- update the current name of hair type and facial hair type
	local index = RaceChangeWindow.updateWearableItemIndex(RCWhairStyles, "HairStyle", RCWhairStyle, true)
	RCWhairStyle = RCWhairStyles[index].id

	-- show facial hair stuff only for human and gargoyle males
	if ( (RCWrace == 1 or RCWrace == 3) and RCWgender == 0 ) then
		index = RaceChangeWindow.updateWearableItemIndex(RCWfacialHairStyles, "FacialHairStyle", RCWfacialHairStyle, true)
		RCWfacialHairStyle = RCWfacialHairStyles[index].id
	end
	
	RaceChangeWindow.ColorSkin()
	RaceChangeWindow.ColorHair()
	
	-- show facial hair stuff only for humans and gargoyles
	if (RCWrace == 1 or RCWrace == 3) then
		RaceChangeWindow.ColorFacialHair()
	end
	
	-- hide the face change selector
	WindowSetShowing (WindowName.."SkinLabel", false)
	WindowSetShowing (WindowName.."SkinStyle", false)
	WindowSetShowing (WindowName.."SkinBackground", false)
	WindowSetShowing (WindowName.."SkinUpButton", false)
	WindowSetShowing (WindowName.."SkinDownButton", false)
	
	-- hide close button of Paperdoll
	WindowSetShowing( WindowName.."PaperdollWindowChrome_UO_WindowCloseButton", false )
	
	Interface.OnCloseCallBack[WindowName] = RaceChangeWindow.UserClosedWindow
end

function RaceChangeWindow.HandleOkButton()
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HandleOkButton() - skin color =  "..StringToWString(tostring(RCWskinColor)))
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HandleOkButton() - RCWhairStyle =  "..StringToWString(tostring(RCWhairStyle)))
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HandleOkButton() - RCWhairColor =  "..StringToWString(tostring(RCWhairColor)))
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HandleOkButton() - RCWfacialHairStyle =  "..StringToWString(tostring(RCWfacialHairStyle)))
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HandleOkButton() - RCWfacialHairColor =  "..StringToWString(tostring(RCWfacialHairColor)))
	
	SendRaceChangeResponse(RCWskinColor, RCWhairStyle, RCWhairColor, RCWfacialHairStyle, RCWfacialHairColor)

	RaceChangeWindow.OnCloseWindow()
end

function RaceChangeWindow.UserClosedWindow()
	SendRaceChangeResponse(0, 0, 0, 0, 0)

	RaceChangeWindow.OnCloseWindow()
end

function RaceChangeWindow.createWearableTable(CSVTable)
	local wearableTable = {}
	local numWearables =  table.getn(CSVTable)

	for i = 1,numWearables do
		-- HACKY IF STATEMENT CHECK BECAUSE CSV TABLE SEEMS TO CONTAIN NIL VALUES
		if not ((CSVTable[i].TileArtId == 0) and (CSVTable[i].StringId == 0))  then
			wearableTable[i] = {id=CSVTable[i].TileArtId, tid=CSVTable[i].StringId}

		end
	end
	
	return wearableTable
end

-- helper function to increment or decrement one unit through wearables table
-- increment = true means increment up one
-- increment = false means decrement down one unit
-- increment = nil means don't increment or decrement
function RaceChangeWindow.updateWearableItemIndex(appearanceTable, appearanceLabel, appearanceStyle, increment)
    local appearanceIndex = 0
    local numStyles = table.getn(appearanceTable)
    local WindowName = RaceChangeWindow.WindowName
    
	for i,v in ipairs(appearanceTable) do
		if (v.id == appearanceStyle) then
			appearanceIndex = i
			break
		end
	end

	local numStyles = table.getn(appearanceTable)

	if (increment) then
	    if (appearanceIndex == numStyles) then
	        appearanceIndex = 1
		else
		    appearanceIndex = appearanceIndex + 1
		end
	elseif (increment == false) then -- decrement
	    if (appearanceIndex == 1) then
	        appearanceIndex = numStyles
		else
		    appearanceIndex = appearanceIndex - 1
		end
	end

	LabelSetText(WindowName..appearanceLabel, GetStringFromTid(appearanceTable[appearanceIndex].tid))
	return appearanceIndex
end

function RaceChangeWindow.ToggleAppearanceItemUp()
	local appearanceIndex
	local WindowName = RaceChangeWindow.WindowName

	if SystemData.ActiveWindow.name == WindowName.."HairUpButton" then
		appearanceIndex = RaceChangeWindow.updateWearableItemIndex(RCWhairStyles, "HairStyle", RCWhairStyle, true)
		RCWhairStyle = RCWhairStyles[appearanceIndex].id
	elseif SystemData.ActiveWindow.name == WindowName.."FacialHairUpButton" then
		if (RCWrace == 1 or RCWrace == 3) then
			appearanceIndex = RaceChangeWindow.updateWearableItemIndex(RCWfacialHairStyles, "FacialHairStyle", RCWfacialHairStyle, true)
			RCWfacialHairStyle = RCWfacialHairStyles[appearanceIndex].id
		end
	end
	
	RaceChangeWindow.UpdateCharacterPaperdoll()
end

function RaceChangeWindow.ToggleAppearanceItemDown()
    local appearanceIndex
    local WindowName = RaceChangeWindow.WindowName

 	if SystemData.ActiveWindow.name == WindowName.."HairDownButton" then
		appearanceIndex = RaceChangeWindow.updateWearableItemIndex(RCWhairStyles, "HairStyle", RCWhairStyle, false)
		RCWhairStyle = RCWhairStyles[appearanceIndex].id
	elseif SystemData.ActiveWindow.name == WindowName.."FacialHairDownButton" then
		if (RCWrace == 1 or RCWrace == 3) then
			appearanceIndex = RaceChangeWindow.updateWearableItemIndex(RCWfacialHairStyles, "FacialHairStyle", RCWfacialHairStyle, false)
			RCWfacialHairStyle = RCWfacialHairStyles[appearanceIndex].id
		end
	end
	RaceChangeWindow.UpdateCharacterPaperdoll()
end

function RaceChangeWindow.ShowColorPicker()
	local WindowName = RaceChangeWindow.WindowName
	
	RaceChangeWindow.HideColorPickerWindows()
	
    if (SystemData.ActiveWindow.name == WindowName.."SkinColorBar") then
    	if (RCWrace == 1) then
	        if  (not(WindowGetShowing(WindowName.."SkinColorPicker"))) then
	            WindowSetShowing(WindowName.."SkinColorPicker",true)       
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorSkin)
	        else
	            WindowSetShowing(WindowName.."SkinColorPicker",false)        
	        end
	    elseif (RCWrace == 2) then
	    	if  (not(WindowGetShowing(WindowName.."ElfSkinColorPicker"))) then
	            WindowSetShowing(WindowName.."ElfSkinColorPicker",true)       
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorSkin)
	        else
	            WindowSetShowing(WindowName.."ElfSkinColorPicker",false)        
	        end
	    elseif (RCWrace == 3) then
	    	if  (not(WindowGetShowing(WindowName.."GargoyleSkinColorPicker"))) then
	            WindowSetShowing(WindowName.."GargoyleSkinColorPicker",true)       
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorSkin)
	        else
	            WindowSetShowing(WindowName.."GargoyleSkinColorPicker",false)        
	        end
	    end     
    elseif (SystemData.ActiveWindow.name == WindowName.."HairColorBar") then
        if (RCWrace == 1) then
	        if  (not(WindowGetShowing(WindowName.."HairColorPicker"))) then
	            WindowSetShowing(WindowName.."HairColorPicker",true)
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorHair)
	        else
	            WindowSetShowing(WindowName.."HairColorPicker",false)
	        end
	    elseif (RCWrace == 2) then
	    	if  (not(WindowGetShowing(WindowName.."ElfHairColorPicker"))) then
	            WindowSetShowing(WindowName.."ElfHairColorPicker",true)
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorHair)
	        else
	            WindowSetShowing(WindowName.."ElfHairColorPicker",false)
	        end
	    elseif (RCWrace == 3) then
	    	if  (not(WindowGetShowing(WindowName.."GargoyleHairColorPicker"))) then
	            WindowSetShowing(WindowName.."GargoyleHairColorPicker",true)
	            ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorHair)
	        else
	            WindowSetShowing(WindowName.."GargoyleHairColorPicker",false)
	        end
	    end
    elseif (SystemData.ActiveWindow.name == WindowName.."FacialHairColorBar") then
		if (RCWrace == 1) then
			if  (not(WindowGetShowing(WindowName.."FacialHairColorPicker"))) then
				WindowSetShowing(WindowName.."FacialHairColorPicker",true)       
				ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorFacialHair)
			else
				WindowSetShowing(WindowName.."FacialHairColorPicker",false)
			end
		elseif (RCWrace == 3) then
			if (not(WindowGetShowing(WindowName.."GargoyleFacialHairColorPicker"))) then
				WindowSetShowing(WindowName.."GargoyleFacialHairColorPicker",true)
				ColorPickerWindow.SetAfterColorSelectionFunction(RaceChangeWindow.ColorFacialHair)
			else
				WindowSetShowing(WindowName.."GargoyleFacialHairColorPicker",false)
			end
        end
    end

end

function RaceChangeWindow.ColorSkin()
    local red, green, blue, alpha
    local WindowName = RaceChangeWindow.WindowName
    if (RCWrace == 1) then
	    RCWskinColor = ColorPickerWindow.colorSelected[WindowName.."SkinColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."SkinColorPicker"])
	elseif (RCWrace == 2) then
	    RCWskinColor = ColorPickerWindow.colorSelected[WindowName.."ElfSkinColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."ElfSkinColorPicker"])
	elseif (RCWrace == 3) then
	    RCWskinColor = ColorPickerWindow.colorSelected[WindowName.."GargoyleSkinColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."GargoyleSkinColorPicker"])

	end
    WindowSetTintColor(WindowName.."SkinColorBar", red, green, blue)    
	RaceChangeWindow.UpdateCharacterPaperdoll()
end

function RaceChangeWindow.ColorHair()
    local red, green, blue, alpha
    local WindowName = RaceChangeWindow.WindowName
    if (RCWrace == 1) then
	    RCWhairColor = ColorPickerWindow.colorSelected[WindowName.."HairColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."HairColorPicker"])
	elseif (RCWrace == 2) then
	    RCWhairColor = ColorPickerWindow.colorSelected[WindowName.."ElfHairColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."ElfHairColorPicker"])
	elseif (RCWrace == 3) then
	    RCWhairColor = ColorPickerWindow.colorSelected[WindowName.."GargoyleHairColorPicker"]
	    red, green, blue, alpha  = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."GargoyleHairColorPicker"])
	end
    WindowSetTintColor(WindowName.."HairColorBar", red, green, blue)
    RaceChangeWindow.UpdateCharacterPaperdoll()    
end

function RaceChangeWindow.ColorFacialHair()
	local red, green, blue, alpha
	local WindowName = RaceChangeWindow.WindowName
	if(RCWrace == 1) then
		RCWfacialHairColor = ColorPickerWindow.colorSelected[WindowName.."FacialHairColorPicker"]
		red, green, blue, alpha = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."FacialHairColorPicker"])
	elseif(RCWrace == 3) then
		RCWfacialHairColor = ColorPickerWindow.colorSelected[WindowName.."GargoyleFacialHairColorPicker"]
		red, green, blue, alpha = HueRGBAValue(ColorPickerWindow.colorSelected[WindowName.."GargoyleFacialHairColorPicker"])
	end
	WindowSetTintColor(WindowName.."FacialHairColorBar", red, green, blue)	
	RaceChangeWindow.UpdateCharacterPaperdoll()
end 

function RaceChangeWindow.HideColorPickerWindows()
	local WindowName = RaceChangeWindow.WindowName
	--Debug.PrintToDebugConsole(L"RaceChangeWindow.HideColorPickerWindows")
	if (RCWrace == 1) then
		WindowSetShowing(WindowName.."SkinColorPicker", false)
		WindowSetShowing(WindowName.."HairColorPicker", false)
		WindowSetShowing(WindowName.."FacialHairColorPicker", false)
	elseif (RCWrace == 2) then
		WindowSetShowing(WindowName.."ElfSkinColorPicker", false)
		WindowSetShowing(WindowName.."ElfHairColorPicker", false)
	elseif (RCWrace == 3) then
		WindowSetShowing(WindowName.."GargoyleSkinColorPicker", false)
		WindowSetShowing(WindowName.."GargoyleHairColorPicker", false)
		WindowSetShowing(WindowName.."GargoyleFacialHairColorPicker", false)
	end	
end

function RaceChangeWindow.UpdatePaperdollTextureSize()
	-- The id for Race Change is hard coded to 1
	local textureData = SystemData.PaperdollTexture[0]
	local WindowName = RaceChangeWindow.WindowName
	
	if( textureData ~= nil) then
		local paperdollName= WindowName.."PaperdollWindowImage"		
		
		WindowSetDimensions(paperdollName, textureData.Width, textureData.Height)
		DynamicImageSetTexture(paperdollName, "paperdoll_special_texture0", 0, 0)

		-- always adjust the offset
		WindowClearAnchors(paperdollName)
		WindowAddAnchor(paperdollName,"center",WindowName.."PaperdollWindow","topleft",textureData.xOffset,textureData.yOffset)			
	end
end

function RaceChangeWindow.UpdateCharacterPaperdoll()
	
	WindowData.RaceChange.Gender = RCWgender
	WindowData.RaceChange.Race = RCWrace       
	WindowData.RaceChange.SkinColor = RCWskinColor
	WindowData.RaceChange.HairType= RCWhairStyle
	WindowData.RaceChange.FacialHairType = RCWfacialHairStyle
	WindowData.RaceChange.HairColor = RCWhairColor
	WindowData.RaceChange.FacialHairColor = RCWfacialHairColor
		
	BroadcastEvent(SystemData.Events.CHARACTER_TOKEN_UPDATE_PAPERDOLL)

end

function RaceChangeWindow.Shutdown()
    UOUnloadCSVTable ("RacesCSV")
    UOUnloadCSVTable ("ElfHairHuesCSV")
    UOUnloadCSVTable ("ElfSkinHuesCSV")
    UOUnloadCSVTable ("GargoyleHornHuesCSV")
    UOUnloadCSVTable ("GargoyleSkinHuesCSV")
    UOUnloadCSVTable ("FemaleElfHairstylesCSV")
    UOUnloadCSVTable ("FemaleGargoyleHornstylesCSV")
    UOUnloadCSVTable ("FemaleHumanHairstylesCSV")
    UOUnloadCSVTable ("MaleElfHairstylesCSV")
    UOUnloadCSVTable ("MaleGargoyleHornstylesCSV")
    UOUnloadCSVTable ("MaleHumanHairstylesCSV")
    
   for i = 1, table.getn (WindowList) do
		DestroyWindow (WindowList[i])
   end
   WindowList = {}	
end

function RaceChangeWindow.OnCloseWindow()
	local WindowName = RaceChangeWindow.WindowName
	
	RaceChangeWindow.Shutdown()
	DestroyWindow (WindowName)
end

