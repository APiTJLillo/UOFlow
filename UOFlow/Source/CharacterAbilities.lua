----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CharacterAbilities = {}

CharacterAbilities.TID = {CharacterAbilities=1112228, WEAPON=1112229, RACIAL=1112230, Weapon=1062759,
							Active=1112231, Index=3010003, Passive=1112232, PrimaryAbility=1062105, SecondaryAbility=1062106}

CharacterAbilities.WEAPONABILITY_OFFSET = 1000
CharacterAbilities.RACIALABILITY_OFFSET = 3000

CharacterAbilities.WEAPONABILITY_MAX = 31

CharacterAbilities.MaxRacialAbilities = 0

function CharacterAbilities.Initialize()
	local windowName = "CharacterAbilities"
	
	WindowUtils.SetWindowTitle(windowName, GetStringFromTid(CharacterAbilities.TID.CharacterAbilities) )

--	ButtonSetText(windowName.."TabButton1", GetStringFromTid(CharacterAbilities.TID.WEAPON))
--	ButtonSetText(windowName.."TabButton2", GetStringFromTid(CharacterAbilities.TID.RACIAL))
	
	--CharacterAbilities.UnselectAllTabs(windowName, 2)
	--CharacterAbilities.SelectTab(windowName, 1)

	CharacterAbilities.InitWeaponTab()
	CharacterAbilities.InitRacialTab()

	WindowRegisterEventHandler( "CharacterAbilities", WindowData.PlayerStatus.Event, "CharacterAbilities.UpdateRacialTab")
	WindowRegisterEventHandler( "CharacterAbilities", SystemData.Events.ABILITY_DISPLAY_ACTIVE, "CharacterAbilities.ActivateWeaponAbility")
	WindowRegisterEventHandler( "CharacterAbilities", SystemData.Events.ABILITY_RESET, "CharacterAbilities.ResetWeaponAbility")
	
	WindowSetShowing(windowName .. "TabWindow1", true)
	WindowSetShowing(windowName .. "TabWindow2", true)
	
	LabelSetText("CharacterAbilitiesTabWindow1ScrollWindowScrollChildWeapon", GetStringFromTid(CharacterAbilities.TID.WEAPON))
	LabelSetText("CharacterAbilitiesTabWindow2ScrollWindowScrollChildRacial", GetStringFromTid(CharacterAbilities.TID.RACIAL))
	local this = windowName
	WindowSetShowing( this.."Chrome", false )
	
	local xSize, ySize
	local scale = 2.0
	texture, xSize, ySize = RequestGumpArt( 11010 )
	local textureSize = xSize
	
	if (textureSize < ySize) then
		textureSize = ySize
	end
	
	
	WindowSetDimensions(  this, (xSize * scale), (ySize * scale) + 20 )
	WindowSetDimensions(  this.."LegacyBook", xSize * scale, ySize * scale )
	DynamicImageSetTexture( this.."LegacyBook", texture, 0, 0 )
	DynamicImageSetTextureScale( this.."LegacyBook", scale )
	
	WindowClearAnchors(this.."LegacyBook")
	WindowAddAnchor( this.."LegacyBook", "topleft", this, "topleft", -60, 0)
	WindowSetShowing( this.."LegacyBook", true )


	WindowUtils.RestoreWindowPosition("CharacterAbilities")
	
end

function CharacterAbilities.Shutdown()
	CharacterAbilities.ShutdownWeaponTab()
	CharacterAbilities.ShutdownRacialTab()
	WindowUtils.SaveWindowPosition("CharacterAbilities")
end

function CharacterAbilities.OnShown()
	if( WindowData.PlayerStatus ~= nil and WindowData.PlayerStatus.PlayerId ~= nil ) then
        local paperdollWindow = "PaperdollWindow"..WindowData.PlayerStatus.PlayerId
        if( DoesWindowNameExist(paperdollWindow) ) then
            ButtonSetPressedFlag(paperdollWindow.."ToggleCharacterAbilities",true)
        end
    end
end

function CharacterAbilities.OnHidden()
	if( WindowData.PlayerStatus ~= nil and WindowData.PlayerStatus.PlayerId ~= nil ) then
        local paperdollWindow = "PaperdollWindow"..WindowData.PlayerStatus.PlayerId
        if( DoesWindowNameExist(paperdollWindow) ) then
            ButtonSetPressedFlag(paperdollWindow.."ToggleCharacterAbilities",false)
        end
    end
end

function CharacterAbilities.ToggleTab()
	local parent = "CharacterAbilities"
	local buttonId = WindowGetId(SystemData.ActiveWindow.name)
	
	CharacterAbilities.UnselectAllTabs("CharacterAbilities", 2)
	CharacterAbilities.SelectTab(parent, buttonId)
end

function CharacterAbilities.UnselectAllTabs(parent, numTabs)
	for i = 1, numTabs do
		local tabName = parent.."TabButton"..i
		local tabSelected = tabName.."TabSelected"
		local tabWindow = parent.."TabWindow"..i
		WindowSetShowing(tabSelected, false)
		WindowSetShowing(tabWindow, false)
		ButtonSetDisabledFlag(tabName, false)
	end
end

function CharacterAbilities.SelectTab(parent, tabNum)
	local tabName = parent.."TabButton"..tabNum
	local tabSelected= tabName.."TabSelected"
	local tabWindow = parent.."TabWindow"..tabNum
	WindowSetShowing(tabSelected, true)
	WindowSetShowing(tabWindow, true)
	ButtonSetDisabledFlag(tabName, true)
end

function CharacterAbilities.InitWeaponTab()
	LabelSetText("CharacterAbilitiesTabWindow1ScrollWindowScrollChildActive", L" --- " .. GetStringFromTid(CharacterAbilities.TID.Active) .. L" --- ")
	LabelSetText("CharacterAbilitiesTabWindow1ScrollWindowScrollChildIndex", L" --- " .. GetStringFromTid(CharacterAbilities.TID.Index) .. L" --- ")
	
	local baseItemName = "CharacterAbilitiesTabWindow1ScrollWindowScrollChildItem"
	
	-- Show primary/secondary weapon abilities
	for i=1,2 do
		local currentWindowName = baseItemName.."Active"..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
		CreateWindowFromTemplate( currentWindowName, "CharacterAbilityDef", "CharacterAbilitiesTabWindow1ScrollWindowScrollChild" )

		WindowClearAnchors(currentWindowName)
		if (i==1) then
 			WindowAddAnchor( currentWindowName, "bottomleft", "CharacterAbilitiesTabWindow1ScrollWindowScrollChildActive", "topleft", -10, 0)
		else
			WindowAddAnchor( currentWindowName, "bottomleft", baseItemName.."Active"..(i-1), "topleft", 0, 0)
		end
		
		local abilityId = EquipmentData.GetWeaponAbilityId(i) + CharacterAbilities.WEAPONABILITY_OFFSET
		local icon, serverId, tid, desctid = GetAbilityData(abilityId)
		local iconTexture, x, y = GetIconData(icon)
		
		DynamicImageSetTexture(currentWindowName.."SquareIcon", iconTexture, x, y)
		
		
		WindowSetShowing(currentWindowName.."Disabled", false)
		
		LabelSetTextColor(currentWindowName.."Name", 0, 0, 0)
		LabelSetText(currentWindowName.."Name", GetStringFromTid(tid))
		
		LabelSetTextColor(currentWindowName.."SubText", 0, 94, 0)
		if (i == 1) then
			LabelSetText(currentWindowName.."SubText", GetStringFromTid(CharacterAbilities.TID.PrimaryAbility))
		elseif (i == 2) then
			LabelSetText(currentWindowName.."SubText", GetStringFromTid(CharacterAbilities.TID.SecondaryAbility))
		end
		WindowSetShowing(currentWindowName.."SubText", true)
		
		WindowSetShowing(currentWindowName, true)
		
		WindowSetId(currentWindowName, abilityId)
		WindowSetId(currentWindowName.."SquareIcon", abilityId)
	end
	
	-- Show all weapon abilities
	for i=1,CharacterAbilities.WEAPONABILITY_MAX do
		local currentWindowName = baseItemName.."All"..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
		CreateWindowFromTemplate( currentWindowName, "CharacterAbilityDef", "CharacterAbilitiesTabWindow1ScrollWindowScrollChild" )

		WindowClearAnchors(currentWindowName)
		if (i==1) then
 			WindowAddAnchor( currentWindowName, "bottomleft", "CharacterAbilitiesTabWindow1ScrollWindowScrollChildIndex", "topleft", -10, 0)
		else
			WindowAddAnchor( currentWindowName, "bottomleft", baseItemName.."All"..(i-1), "topleft", 0, 0)
		end
		
		local abilityId = i + CharacterAbilities.WEAPONABILITY_OFFSET
		local icon, serverId, tid, desctid = GetAbilityData(abilityId)
		local iconTexture, x, y = GetIconData(icon)
		
		DynamicImageSetTexture(currentWindowName.."SquareIcon", iconTexture, x, y)
		
		WindowSetShowing(currentWindowName.."Disabled", false)
		WindowSetAlpha(currentWindowName.."SquareIcon", 0.4)
		LabelSetTextColor(currentWindowName.."Name", 115, 115, 115)
		LabelSetText(currentWindowName.."Name", GetStringFromTid(tid))
		
		WindowSetShowing(currentWindowName.."SubText", false)
		
		WindowSetShowing(currentWindowName, true)
		
		WindowSetId(currentWindowName, abilityId)
		WindowSetId(currentWindowName.."SquareIcon", abilityId)
	end
end



function CharacterAbilities.ShutdownWeaponTab()
	local baseItemName = "CharacterAbilitiesTabWindow1ScrollWindowScrollChildItem"
	
	for i=1,2 do
		local currentWindowName = baseItemName.."Active"..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
	end
	
	for i=1,CharacterAbilities.WEAPONABILITY_MAX do
		local currentWindowName = baseItemName.."All"..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
	end
end

function CharacterAbilities.UpdateWeaponAbilities()
	local baseItemName = "CharacterAbilitiesTabWindow1ScrollWindowScrollChildItem"
	
	if (not DoesWindowExist(baseItemName.."Active1") or not DoesWindowExist(baseItemName.."Active2")) then
		CharacterAbilities.InitWeaponTab()
	end
	
	for i=1,2 do
		local currentWindowName = baseItemName.."Active"..i
		
		local abilityId = EquipmentData.GetWeaponAbilityId(i) + CharacterAbilities.WEAPONABILITY_OFFSET
		local icon, serverId, tid, desctid = GetAbilityData(abilityId)
		local iconTexture, x, y = GetIconData(icon)
		
		DynamicImageSetTexture(currentWindowName.."SquareIcon", iconTexture, x, y)
			--	DynamicImageSetTexture( currentWindowName .."SquareIconBG", MiniTexturePack.DB[MiniTexturePack.Current].texture .. "Icon", 64, 64 )
		LabelSetText(currentWindowName.."Name", GetStringFromTid(tid))
		
		WindowSetId(currentWindowName, abilityId)
		WindowSetId(currentWindowName.."SquareIcon", abilityId)
	end
end

CharacterAbilities.ManaBefore = 0
function CharacterAbilities.ActivateWeaponAbility()
	local abilityId = GameData.Abilities.ActiveAbility
	local type = GameData.Abilities.ActiveAbilityType

	if( type == SystemData.UserAction.TYPE_WEAPON_ABILITY ) then
		local abilityIndex = 0		
		if( abilityId == EquipmentData.CurrentWeaponAbilities[EquipmentData.WEAPONABILITY_PRIMARY] ) then
			abilityIndex = EquipmentData.WEAPONABILITY_PRIMARY
		elseif( abilityId == EquipmentData.CurrentWeaponAbilities[EquipmentData.WEAPONABILITY_SECONDARY] ) then
			abilityIndex = EquipmentData.WEAPONABILITY_SECONDARY
		end
		
		local baseItemName = "CharacterAbilitiesTabWindow1ScrollWindowScrollChildItem"
		if (not DoesWindowExist(baseItemName.."Active1") or not DoesWindowExist(baseItemName.."Active2")) then
			CharacterAbilities.InitWeaponTab()
		end
		GameData.UseRequests.UseSpecialMove = abilityId
		Interface.SpecialMoveUseRequest()
		CharacterAbilities.ManaBefore = WindowData.PlayerStatus.CurrentMana
		for i=1,2 do
			if (i == abilityIndex) then
				local currentWindowName = baseItemName.."Active"..i
				WindowSetTintColor(currentWindowName.."SquareIcon",255,0,0)
			end
		end
	end
end

function CharacterAbilities.ResetWeaponAbility()
	local baseItemName = "CharacterAbilitiesTabWindow1ScrollWindowScrollChildItem"
	if (not DoesWindowExist(baseItemName.."Active1") or not DoesWindowExist(baseItemName.."Active2")) then
		CharacterAbilities.InitWeaponTab()
	end
	local lmcMana = AbilitiesInfo.GetManaCost(Interface.LastSpecialMove) or 0
	if (WindowData.PlayerStatus.CurrentMana - CharacterAbilities.ManaBefore) < lmcMana  then
		Interface.OnSpecialMoveUsedSuccessfully(Interface.LastSpecialMove)
		Interface.LastSpecialMoveTime = 3		
	end
	for i=1,2 do
		local currentWindowName = baseItemName.."Active"..i
		WindowSetTintColor(currentWindowName.."SquareIcon",255,255,255)
	end
end

function CharacterAbilities.InitRacialTab()
	local baseItemName = "CharacterAbilitiesTabWindow2ScrollWindowScrollChildItem"
	
	CharacterAbilities.MaxRacialAbilities = GetMaxRacialAbilities()
	
	-- Show racial abilities
	for i=1,CharacterAbilities.MaxRacialAbilities do
		local currentWindowName = baseItemName..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
		CreateWindowFromTemplate( currentWindowName, "CharacterAbilityDef", "CharacterAbilitiesTabWindow2ScrollWindowScrollChild" )

		WindowClearAnchors(currentWindowName)
		if (i==1) then
 			WindowAddAnchor( currentWindowName, "topleft", "CharacterAbilitiesTabWindow2ScrollWindowScrollChild", "topleft", 0, 30)
		else
			WindowAddAnchor( currentWindowName, "bottomleft", baseItemName..(i-1), "topleft", 0, 0)
		end
		
		local abilityId = GetRacialAbilityId(i) + CharacterAbilities.RACIALABILITY_OFFSET
		local icon, serverId, tid = GetAbilityData(abilityId)
		local iconTexture, x, y = GetIconData(icon)
		
		DynamicImageSetTexture(currentWindowName.."SquareIcon", iconTexture, x, y)
			
		WindowSetShowing(currentWindowName.."Disabled", false)
		
		LabelSetTextColor(currentWindowName.."Name", 0, 0, 0)
		LabelSetText(currentWindowName.."Name", GetStringFromTid(tid))
		
		if (serverId == 0) then
			LabelSetTextColor(currentWindowName.."SubText", 0, 94, 0)
			LabelSetText(currentWindowName.."SubText", GetStringFromTid(CharacterAbilities.TID.Passive))
			WindowSetShowing(currentWindowName.."SubText", true)
		else
			WindowSetShowing(currentWindowName.."SubText", false)
		end
		
		WindowSetShowing(currentWindowName, true)
		
		WindowSetId(currentWindowName, abilityId)
		WindowSetId(currentWindowName.."SquareIcon", abilityId)
	end
	
	ScrollWindowUpdateScrollRect("CharacterAbilitiesTabWindow2ScrollWindow")
end

function CharacterAbilities.ShutdownRacialTab()
	local baseItemName = "CharacterAbilitiesTabWindow2ScrollWindowScrollChildItem"
	
	for i=1,CharacterAbilities.MaxRacialAbilities do
		local currentWindowName = baseItemName..i
		
		if (DoesWindowExist(currentWindowName)) then
			DestroyWindow(currentWindowName)
		end
	end
end

function CharacterAbilities.UpdateRacialTab()
	local windowName = "CharacterAbilities"	
	if (DoesWindowNameExist(windowName) and CharacterAbilities.MaxRacialAbilities ~= GetMaxRacialAbilities()) then
		CharacterAbilities.ShutdownRacialTab()
		CharacterAbilities.InitRacialTab()
	end
end

function CharacterAbilities.ItemMouseOver()
	local id = WindowGetId(SystemData.ActiveWindow.name)
	
	local icon, serverId, tid, desctid, weapons = GetAbilityData(id)
	
	local weaponsStr = L""
    if(weapons ~= nil and weapons ~= "") then
		weaponsStr = L"<BR>== "..GetStringFromTid(CharacterAbilities.TID.Weapon)..L" ==<BR>"..StringToWString(weapons)
    end
	
	local itemData = { windowName = this,
						itemId = id,
						itemType = WindowData.ItemProperties.TYPE_ACTION,
						actionType = SystemData.UserAction.TYPE_SPELL,
						detail = ItemProperties.DETAIL_LONG,
						body = weaponsStr }
						
	ItemProperties.SetActiveItem(itemData)
end

function CharacterAbilities.ItemLButtonDown()
	local iconId = WindowGetId(SystemData.ActiveWindow.name)
	
	if (iconId > CharacterAbilities.WEAPONABILITY_OFFSET and iconId < CharacterAbilities.WEAPONABILITY_OFFSET + 1000) then
		for i=1,2 do
			local abilityId = EquipmentData.GetWeaponAbilityId(i) + CharacterAbilities.WEAPONABILITY_OFFSET
			if (abilityId == iconId) then
				DragSlotSetActionMouseClickData(SystemData.UserAction.TYPE_WEAPON_ABILITY,i,iconId)
				break
			end
		end
	elseif (iconId > CharacterAbilities.RACIALABILITY_OFFSET and iconId < CharacterAbilities.RACIALABILITY_OFFSET + 1000) then
		local icon, serverId = GetAbilityData(iconId)
		if (serverId ~= 0) then
			DragSlotSetActionMouseClickData(SystemData.UserAction.TYPE_RACIAL_ABILITY,serverId,iconId)
		end
	end
end

function CharacterAbilities.ItemLButtonUp()
	local iconId = WindowGetId(SystemData.ActiveWindow.name)
	
	if (iconId > CharacterAbilities.WEAPONABILITY_OFFSET and iconId < CharacterAbilities.WEAPONABILITY_OFFSET + 1000) then
		for i=1,2 do
			local abilityId = EquipmentData.GetWeaponAbilityId(i) + CharacterAbilities.WEAPONABILITY_OFFSET
			if (abilityId == iconId) then
				UserActionUseWeaponAbility(i)
			end
		end
	elseif (iconId > CharacterAbilities.RACIALABILITY_OFFSET and iconId < CharacterAbilities.RACIALABILITY_OFFSET + 1000) then
		local icon, serverId = GetAbilityData(iconId)
		if (serverId ~= 0) then
			UserActionUseRacialAbility(serverId)
		end
	end
end