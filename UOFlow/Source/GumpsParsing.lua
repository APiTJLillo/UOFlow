----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

GumpsParsing = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

GumpsParsing.ParsedGumps = {} -- contains the name of all the identified gumps

GumpsParsing.ToShow = {}

GumpsParsing.SOSTids = {1153537, 1153538, 1153539, 1153540, 1153541, 1153542, 1153543, 1153544, 1153545, 1153546, 1153547, 1153548, 1153549, 1153550, 1153584, 1153585, 1153586}


GumpsParsing.GumpMaps = {
--		ID			NAME							  SHOW?
	[999002] = 	{name="TCGump",						show=1};
	[10014]  = 	{name="Virtues",					show=1};
	[805]  = 	{name="QuestLog",					show=1};
	-- GUILD
	[725]  = 	{name="GuildMenuCreate",			show=1};
	[726]  = 	{name="GuildInvite",				show=1};
	[727]  = 	{name="GuildMenuRoster",			show=1};
	[728]  = 	{name="GuildMenuPlayerDetails", 	show=1};
	[729]  = 	{name="GuildMenuDiplomacy",			show=1};
	[730]  = 	{name="GuildMenuRelationship",		show=1};
	[731]  = 	{name="GuildMenuWar",				show=1};
	[733]  = 	{name="GuildMenuMyGuild",			show=1};
	[734]  = 	{name="GuildMenuAdvSearch",			show=1};
	
	-- HELP
	[666]  = 	{name="HelpMenu",					show=1};
	[672] = 	{name="HelpMenu",					show=1}; -- "GUMP_PAGE_TEXTENTRY"
	[296] = 	{name="HelpMenu",					show=1}; -- "GUMP_STUCK_PLAYER"
	[9019] = 	{name="HelpMenu",					show=1}; -- "GUMP_TARGET_PETITION_TARGET"
	[9020] = 	{name="HelpMenu",					show=1}; -- "GUMP_TYPE_PETITION_TARGET"
	[9021] = 	{name="HelpMenu",					show=1}; -- "GUMP_SELECT_PETITION_TARGET"
	
	[999019]  =	{name="SOS",						show=0};
	
	[999060]  =	{name="LoyaltyRating",				show=1};
	
	[460]  =	{name="CraftingMenu",				show=1};
	[685]  =	{name="CraftingMenu",				show=1};
	
	[464]  =	{name="HousePlacementMenu",			show=1};
	[452]  =	{name="VeteranRewardMain",			show=1};
	[453]  =	{name="VeteranRewardCategories",	show=1};
	[9083]  =	{name="HTML_Book",					show=0};
	[999074]  =	{name="TitlesMenu",					show=1};
	[999071]  =	{name="InsuranceMenu",				show=1};
	[9178]  =	{name="CityStone",					show=1};
	[17000]  =	{name="CleanupBritannia",			show=1};
	[800]  =	{name="QuestOffer",					show=1};
	[806]  =	{name="QuestConversation",			show=1};
	[475]  =	{name="AnimalLore",					show=1};
	[600]  =	{name="Moongate",					show=1};
	[9008]  =	{name="BulletinBoard",				show=1};
	[999059]  =	{name="ImbuingMenu",				show=1};
	[455]  =	{name="BODOffer",					show=1};
	[456]  =	{name="BOD",						show=1};
	[403]  =	{name="SixMonthsReward",			show=0};
	
	-- VENDOR SEARCH
	[999112]  =	{name="VendorSearch",				show=1};
	[999113]  =	{name="VendorSearchResults",		show=1};
	[999115]  =	{name="VendorSearchSearching",		show=1};
	
	-- PLANTS
	[29842]	 =	{name="Plant",						show=1};		
	[29582]	 =	{name="PlantEmptyBowl",				show=1};		
	[22222]	 =	{name="PlantReproduction",			show=1};		
	
	[100001] =	{name="TransferCrateWarning",		show=1};
	[999057] =	{name="EnchantSpell",				show=1};
	[9014] =	{name="IconsGump",					show=1}; -- Used for all choice with icons like animal form, polymorph, heritage token, etc...
	[658]  =	{name="SummonFamiliarMenu",			show=1};
	
	[999013] =	{name="CharacterCopyMain",			show=1};
	[200001] =	{name="CharacterCopyShardSelect",	show=1};
	[300001] =	{name="TransferCheckPacking",		show=1}; --character copy/transfer check packing and final confirm
	[300001] =	{name="TransferCheckPacking",		show=1}; --character copy/transfer check packing and final confirm
	[498] =		{name="RunicAtlas",					show=0}; 

	
}


----------------------------------------------------------------
-- GumpsParsing Functions
----------------------------------------------------------------

function GumpsParsing.CheckGumpType(timePassed)
	if not GumpData then
		return
	end

	ok, err = pcall(GumpsParsing.MainParsingCheck, timePassed)	
	Interface.ErrorTracker(ok, err)

	ok, err = pcall(GumpsParsing.ShowHide, timePassed)	
	Interface.ErrorTracker(ok, err)
	
end

-- assign the parent window name and adds the text labels to the structure
function GumpsParsing.MainParsingCheck(timePassed)

	for gumpID, data in pairs(GumpData.Gumps) do
		if not gumpID then	
			continue
		end
		

		if GumpsParsing.ParsedGumps[gumpID] then
			continue
		end	
				
		if not GumpData.Gumps[gumpID].windowName then -- FIX for null main gump window name
			GumpData.Gumps[gumpID].windowName = GenericGump.LastGump
			GenericGump.LastGump = ""
		end		
	
		GenericGump.GumpsList[GumpData.Gumps[gumpID].windowName] = gumpID		

		if GumpsParsing.GumpMaps[gumpID] then
			GumpsParsing.ParsedGumps[gumpID] =  GumpsParsing.GumpMaps[gumpID].name
			GumpsParsing.ToShow[gumpID] = GumpsParsing.GumpMaps[gumpID].show
			if GumpsParsing.GumpMaps[gumpID].name == "SOS" then
				GumpsParsing.SOSGump(data)
				GumpsParsing.DestroyGump(gumpID)
			elseif GumpsParsing.GumpMaps[gumpID].name == "CraftingMenu" then
				if GumpData.Gumps[gumpID].Labels[1].tid == 1044001 then
					GumpsParsing.ParsedGumps[gumpID] = "AlchemyMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044002 then
					GumpsParsing.ParsedGumps[gumpID] = "BlacksmithMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044003 then
					GumpsParsing.ParsedGumps[gumpID] = "CookingMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044004 then
					GumpsParsing.ParsedGumps[gumpID] = "CarpentryMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044005 then
					GumpsParsing.ParsedGumps[gumpID] = "TailoringMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044006 then
					GumpsParsing.ParsedGumps[gumpID] = "BowcraftMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044007 then
					GumpsParsing.ParsedGumps[gumpID] = "TinkeringMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044008 then
					GumpsParsing.ParsedGumps[gumpID] = "CartographyMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044009 then
					GumpsParsing.ParsedGumps[gumpID] = "InscriptionMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044500 then
					GumpsParsing.ParsedGumps[gumpID] = "MasonryMenu"
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1044622 then
					GumpsParsing.ParsedGumps[gumpID] = "GlassblowingMenu"
				end
			elseif GumpsParsing.GumpMaps[gumpID].name == "VendorSearch" then
				if not DoesWindowNameExist(VendorSearch.WindowName) then
					CreateWindow(VendorSearch.WindowName, true)
				else
					VendorSearch.UpdateButtonsMap()
					VendorSearch.SetLoading(false)
				end
				GumpsParsing.ToShow[gumpID] = 0
			elseif GumpsParsing.GumpMaps[gumpID].name == "HTML_Book" then				
				if GumpData.Gumps[gumpID].Labels[1].tid == 1150074 then
					GumpsParsing.ParsedGumps[gumpID] = "CorruptedCrystalPortal"
					CrystalPortal.Toggle()
					GumpsParsing.DestroyGump(gumpID)
				elseif GumpData.Gumps[gumpID].Labels[1].tid == 1113945  then
					GumpsParsing.ParsedGumps[gumpID] = "CrystalPortal"
					CrystalPortal.Toggle()
					GumpsParsing.DestroyGump(gumpID)
				else
					GumpsParsing.ToShow[gumpID] = 1
				end				
			elseif GumpsParsing.GumpMaps[gumpID].name == "SixMonthsReward" then
				GumpsParsing.SixMonthsRewardGump()		
			elseif GumpsParsing.GumpMaps[gumpID].name ==  "TransferCrateWarning" then
				Interface.UnpackTransferCrate = true
			elseif GumpsParsing.GumpMaps[gumpID].name ==  "SummonFamiliarMenu" and Interface.ForceFamiliar ~= 0 then
				local button = Interface.ForceFamiliar
				if SpellsInfo.SumonFamiliarSkillRequirements(button) == 1 then
					button = 0
				end
				if button ~= 0 then
					GumpsParsing.PressButton(gumpID, Interface.ForceFamiliar)
					GumpsParsing.ToShow[gumpID] = 1
				end
			elseif GumpsParsing.GumpMaps[gumpID].name ==  "EnchantSpell" and Interface.ForceEnchant ~= 0 then			
					GumpsParsing.PressButton(gumpID, Interface.ForceEnchant)
					GumpsParsing.ToShow[gumpID] = 0	
			elseif GumpsParsing.GumpMaps[gumpID].name ==  "RunicAtlas" then					
					for label, data in pairs(GumpData.Gumps[gumpID].Labels) do						
						local labelGumpName  = "GenericGumpItem"..tostring(label)
						if(DoesWindowNameExist(labelGumpName)) then
							-- Skip of non actual labels			
							local newr, newg, newb = LabelGetTextColor(labelGumpName)
							if(newr == nil or newg == nil or newb == nil )then								
								continue
							end

							local myRGB = { r=math.floor(newr), g=math.floor(newg), b=math.floor(newb) }
							local OriginalLabelColors = { malas={ r=160, g=160, b=176 }, trammel={ r=144, g=96, b=240 }, tokuno={ r=216, g=240, b=240 }, felucca={ r=144, g=240, b=192 }, termer={ r=192, g=48, b=48 } }														
							local labelColor = {r=146, g=0, b=0} -- default select							

							if( myRGB.r == OriginalLabelColors.trammel.r and myRGB.g == OriginalLabelColors.trammel.g and myRGB.b == OriginalLabelColors.trammel.b ) then								
								labelColor = LegacyRunebook.LegacyLabelColors.trammel
							elseif( myRGB.r == OriginalLabelColors.felucca.r and myRGB.g == OriginalLabelColors.felucca.g and myRGB.b == OriginalLabelColors.felucca.b ) then								
								labelColor = LegacyRunebook.LegacyLabelColors.felucca
							elseif( myRGB.r == OriginalLabelColors.malas.r and myRGB.g == OriginalLabelColors.malas.g and myRGB.b == OriginalLabelColors.malas.b ) then								
								labelColor = LegacyRunebook.LegacyLabelColors.malas							
							elseif ( myRGB.r == OriginalLabelColors.tokuno.r and myRGB.g == OriginalLabelColors.tokuno.g and myRGB.b == OriginalLabelColors.tokuno.b ) then								
								labelColor = LegacyRunebook.LegacyLabelColors.tokuno
							elseif ( myRGB.r == OriginalLabelColors.termer.r and myRGB.g == OriginalLabelColors.termer.g and myRGB.b == OriginalLabelColors.termer.b ) then								
								labelColor = LegacyRunebook.LegacyLabelColors.termer
							elseif ( myRGB.r == 0 and myRGB.g == 0 and myRGB.b == 0 ) then								
								labelColor = LegacyRunebook.DefaultItemLabel							
							end
							LabelSetTextColor( labelGumpName, labelColor.r, labelColor.g, labelColor.b )
						end						
					end
					GumpsParsing.ToShow[gumpID] = 1										
			elseif GumpsParsing.GumpMaps[gumpID].name ==  "IconsGump" then				
				if GumpData.Gumps[gumpID].Labels[2] and GumpData.Gumps[gumpID].Labels[2].tid == 1063394 and Interface.ForceAnimal ~= 0 then					
					GumpsParsing.ParsedGumps[gumpID] = "AnimalFormMenu"
					local button = SpellsInfo.GetButtonID(Interface.ForceAnimal)
					if  button ~= 0 then
						GumpsParsing.PressButton(gumpID, button)
						GumpsParsing.ToShow[gumpID] = 0
					else
						GumpsParsing.ToShow[gumpID] = 1
					end					
				elseif GumpData.Gumps[gumpID].Labels[2] and GumpData.Gumps[gumpID].Labels[2].tid == 1080151 and Interface.ForceSpellTrigger ~= 0 then
					GumpsParsing.ParsedGumps[gumpID] = "SpellTriggerMenu"					
					local button = SpellsInfo.GetButtonIDST(Interface.ForceSpellTrigger)
					if button ~= 0 then
						GumpsParsing.PressButton(gumpID, Interface.ForceSpellTrigger)
						GumpsParsing.ToShow[gumpID] = 0
					else
						GumpsParsing.ToShow[gumpID] = 1
					end
				elseif GumpData.Gumps[gumpID].Labels[2] and GumpData.Gumps[gumpID].Labels[2].tid == 1015234 and Interface.ForcePolymorph ~= 0 then
					GumpsParsing.ParsedGumps[gumpID] = "PolymorphMenu"					
					local num = Interface.ForcePolymorph + 1
					if num >= 12 then
						num = num + 2
					end
					GumpsParsing.PressButton(gumpID, num)
					GumpsParsing.ToShow[gumpID] = 0									
				end				
			end
		else
			GumpsParsing.ToShow[gumpID] = 1
		end
	end
end

function GumpsParsing.DestroyGump(gumpID)
	if GumpData.Gumps[gumpID].windowName and DoesWindowNameExist(GumpData.Gumps[gumpID].windowName) then
		local windowName = GumpData.Gumps[gumpID].windowName
		DestroyWindow(GumpData.Gumps[gumpID].windowName)
		GumpsParsing.ParsedGumps[gumpID] = nil
		GumpsParsing.ToShow[gumpID] = nil
		GenericGump.GumpsList[windowName] = nil
	else
		GumpsParsing.ParsedGumps[gumpID] = nil
		GumpsParsing.ToShow[gumpID] = nil
		GenericGump.GumpsList[windowName] = nil
	end
end

function GumpsParsing.PressButton(gumpID, buttonID)
	if not GumpData.Gumps[gumpID] then
		return
	end
	local gumpId = WindowGetId(GumpData.Gumps[gumpID].windowName)
	if gumpId and GumpData.Gumps[gumpID].Buttons[buttonID] and DoesWindowNameExist(GumpData.Gumps[gumpID].Buttons[buttonID]) then
		GenericGumpOnClicked(gumpId, GumpData.Gumps[gumpID].Buttons[buttonID])
	end
end

function GumpsParsing.TextentryGetText(gumpID, TextentryID)
	local gumpId = WindowGetId(GumpData.Gumps[gumpID].windowName)
	if gumpId and GumpData.Gumps[gumpID].TextEntry[TextentryID] and DoesWindowNameExist(GumpData.Gumps[gumpID].TextEntry[TextentryID]) then
		return TextEditBoxGetText(GumpData.Gumps[gumpID].TextEntry[TextentryID])
	end
end

function GumpsParsing.ShowHide(timePassed)
	if not GumpData then
		return
	end

	for gumpID, value in pairs(GumpData.Gumps) do
		if GumpData.Gumps[gumpID].windowName and DoesWindowNameExist(GumpData.Gumps[gumpID].windowName) then
			if(GumpsParsing.ToShow[gumpID] ~= nil )then
				local showGump = GumpsParsing.ToShow[gumpID] == 1
				if(showGump ~= WindowGetShowing(GumpData.Gumps[gumpID].windowName))then						
						WindowSetShowing(GumpData.Gumps[gumpID].windowName, showGump)
				end
			end
		end

	end
end

function GumpsParsing.SixMonthsRewardGump() -- 6 months reward message Management
	local OKButton = { textTid=UO_StandardDialog.TID_OKAY, callback=function() GumpsParsing.PressButton(403, 1) end }
	local cancelButton = { textTid=UO_StandardDialog.TID_CANCEL, callback=function() GumpsParsing.PressButton(403, 2) end }
	local body = WindowUtils.translateMarkup(GetStringFromTid(1076664))
	
	if DoesWindowNameExist("6MonthsRewardDialog") then
		DestroyWindow("6MonthsRewardDialog")
	end

	local DestroyConfirmWindow = 
				{
					windowName = "6MonthsReward",
					body = body,
					buttons = { OKButton, cancelButton }
				}
	UO_StandardDialog.CreateDialog(DestroyConfirmWindow)
	local w, h = WindowGetDimensions("6MonthsRewardDialog")
	WindowSetDimensions("6MonthsRewardDialog",w,230)
end

function GumpsParsing.SOSGump(data) -- SOS Marker Management
		
	for labelID, labelData in pairs(data.Labels) do
		for i = 1, #GumpsParsing.SOSTids do
			if labelData.tid == GumpsParsing.SOSTids[i] then
				
				local sosText = ReplaceTokens(GetStringFromTid(labelData.tid), labelData.tidParms)
				
				local latVal, latDir, longVal, longDir = GumpsParsing.GetSOSCoords(labelData.tidParms[1])
				
				
				local x,y = MapCommon.ConvertToXYMinutes(latVal, longVal, latDir, longDir, 1, 1)
				local sosID = Interface.LastItem 
				
				local TrammelButton = { textTid=1012000 , callback=function() GumpsParsing.CreateSOSWaypoint(sosID, 1, x, y) end }
				local FeluccaButton = { textTid=1012001 , callback=function() GumpsParsing.CreateSOSWaypoint(sosID, 0, x, y) end }
				local cancelButton = { textTid=3000091}
				local body = sosText ..  L"\n\n" .. GetStringFromTid(1079482) .. L"?"
				
				if DoesWindowNameExist("SoSDialog") then
					DestroyWindow("SoSDialog")
				end

				local DestroyConfirmWindow = 
							{
								windowName = "SoS",
								titleTid = 1041081,
								body = body,
								buttons = { TrammelButton, FeluccaButton, cancelButton }
							}
				UO_StandardDialog.CreateDialog(DestroyConfirmWindow)
				local w, h = WindowGetDimensions("SoSDialog")
				WindowSetDimensions("SoSDialog",w,350)
			end 
		end
	end

end

function GumpsParsing.CreateSOSWaypoint(sosID, map, x, y)
	local waypointID = UOCreateUserWaypoint( MapCommon.WaypointCustomType, x, y, map, L"Sunken Ship" .. L"_ICON_100010_SCALE_" .. 0.69 )
	Interface.SOSWaypoints[sosID] = waypointID
	MapCommon.UpdateWaypoints(MapCommon.ActiveView)
end

----------------------------------------------------------------
-- GumpsParsing Utilities
----------------------------------------------------------------

function GumpsParsing.GetSOSCoords(coords)
								
	local commaPos = wstring.find(coords, L"[,]")
	
	local first = wstring.sub(coords, 1, commaPos - 1)
	first = wstring.gsub(first, L"o ", L".")
	first = wstring.gsub(first, L"'", L"")
	first = wstring.gsub(first, L" ", L"")
	local latDir = wstring.sub(first, -1)
	local latVal = wstring.sub(first,1, -2)

	local second = wstring.sub(coords, commaPos + 3, -1)
	second = wstring.gsub(second, L"o ", L".")
	second = wstring.gsub(second, L"'", L"")
	second = wstring.gsub(second, L" ", L"")
	
	local longDir = wstring.sub(second, -1)
	
	local longVal = wstring.sub(second,1, -2)

	if Interface.DebugMode then
		Debug.Print(latVal .. L"+" .. latDir .. L" - " .. longVal .. L"+" .. longDir )
	end
	return tonumber(latVal), latDir, tonumber(longVal), longDir
end