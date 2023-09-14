----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

PetWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

PetWindow.tid = { PET = 1077432}
PetWindow.OffetSize = 45
PetWindow.windowX = 175
PetWindow.windowY = 60
PetWindow.windowOffset = 5
PetWindow.Locked = false
PetWindow.CheckTime = 1
PetWindow.Delta = 1
PetWindow.PetWindowHidden = false
PetWindow.SortedPet = {}

PetWindow.CloseLeft= true

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function PetWindow.Initialize()
	local windowName = "PetWindow"
	local titleName = windowName.."ShowViewName"
	local hideTitleName = windowName.."HideViewName"
	LabelSetText(titleName, GetStringFromTid(PetWindow.tid.PET) )
	
	LabelSetText(hideTitleName, GetStringFromTid(PetWindow.tid.PET) )
	
	RegisterWindowData(WindowData.Pets.Type, 0)	
	WindowRegisterEventHandler( "PetWindow", WindowData.Pets.Event, "PetWindow.UpdatePet")		
	
	if (SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_ENU) then
		LabelSetFont(titleName,  "UO_DefaultText", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)
		LabelSetFont(hideTitleName,  "UO_DefaultText", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)
	end
	
	WindowUtils.RestoreWindowPosition("PetWindow", false)
	
	
	WindowSetTintColor(windowName .. "ShowViewTitleBar", 0,0,0)
	WindowSetAlpha(windowName .. "ShowViewFrame", 0.5)
	WindowSetScale(windowName, SystemData.Settings.Interface.customUiScale * 0.80)

	PetWindow.ButtonRotation()
	WindowClearAnchors("PetWindowHideView")
	if (PetWindow.CloseLeft) then
		WindowAddAnchor("PetWindowHideView", "topleft", "PetWindow", "topleft", 0, 0 )
	else
		WindowAddAnchor("PetWindowHideView", "topright", "PetWindow", "topright", 0, 0 )
	end
	if (PetWindow.PetWindowHidden) then
		PetWindow.HidePet()
	else
		PetWindow.ShowPet()
	end
	
	PetWindow.Locked = Interface.LoadBoolean( "PetWindowLocked", PetWindow.Locked )	
	local texture = "UO_Core"
	if ( PetWindow.Locked ) then		
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_NORMAL, texture, 69,341)
		ButtonSetTexture(windowName.."Lock",InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, texture, 92,341)
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED, texture, 92,341)
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, texture, 92,341)
	else
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_NORMAL, texture, 117,341)
		ButtonSetTexture(windowName.."Lock",InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, texture, 142,341)
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED, texture, 142,341)
		ButtonSetTexture(windowName.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, texture, 142,341)		
	end
	
end

function PetWindow.Shutdown()
	local windowName = "PetWindow"
	local showName = windowName.."ShowView"
	SnapUtils.SnappableWindows[showName] = nil
	
	UnregisterWindowData(WindowData.Pets.Type, 0)	
	WindowUtils.SaveWindowPosition(windowName)
end

function PetWindow.HideAll()
	local windowName = "PetWindow"
	
	WindowSetShowing(windowName, false)
end

function PetWindow.ShowWindow()
	local windowName = "PetWindow"
	WindowSetShowing(windowName, true)
	
end

function PetWindow.LockTooltip()
	local windowname = WindowUtils.GetActiveDialog()

	if ( PetWindow.Locked  ) then
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1111696))
	else
		Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1111697))
	end
	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function PetWindow.LockMe()
	local this = "PetWindow"
		
	PetWindow.Locked = not PetWindow.Locked
	Interface.SaveBoolean( "PetWindowLocked", PetWindow.Locked )
	
	local texture = "UO_Core"
	if ( PetWindow.Locked  ) then		
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_NORMAL, texture, 69,341)
		ButtonSetTexture(this.."Lock",InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, texture, 92,341)
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED, texture, 92,341)
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, texture, 92,341)
	else
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_NORMAL, texture, 117,341)
		ButtonSetTexture(this.."Lock",InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, texture, 142,341)
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED, texture, 142,341)
		ButtonSetTexture(this.."Lock", InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, texture, 142,341)		
	end

end

function PetWindow.Lock()
	if PetWindow.PetWindowHidden then
		if (PetWindow.Locked) then
			ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154856),0,"unlock",2,false)
		else
			ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154857),0,"lock",2,false)
		end
	end
	if (PetWindow.CloseLeft) then
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154845),0,"closeRight",2,false)
	else
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154846),0,"closeLeft",2,false)
	end
	ContextMenu.ActivateLuaContextMenu(PetWindow.ContextMenuCallback)
end

function PetWindow.ContextMenuCallback( returnCode, param )	
	if ( returnCode=="unlock" ) then
		PetWindow.Locked = false 
		Interface.SaveBoolean( "PetWindowLocked", PetWindow.Locked  )
	elseif ( returnCode=="lock" ) then
		PetWindow.Locked = true 
		Interface.SaveBoolean( "PetWindowLocked", PetWindow.Locked  )
	elseif ( returnCode=="closeRight" ) then
		PetWindow.CloseLeft = false
		Interface.SaveBoolean( "PetWindowCloseLeft", PetWindow.CloseLeft  )
		WindowClearAnchors("PetWindowHideView")
		WindowAddAnchor("PetWindowHideView", "topright", "PetWindow", "topright", 0, 0 )
		PetWindow.ButtonRotation()
	elseif ( returnCode=="closeLeft" ) then
		PetWindow.CloseLeft = true 
		Interface.SaveBoolean( "PetWindowCloseLeft", PetWindow.CloseLeft  )
		WindowClearAnchors("PetWindowHideView")
		WindowAddAnchor("PetWindowHideView", "topleft", "PetWindow", "topleft", 0, 0 )
		PetWindow.ButtonRotation()
	end
end

function PetWindow.OnLButtonUp()
	local mobileId = WindowGetId(SystemData.ActiveWindow.name)
	
	if(SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM) then
		DragSlotDropObjectToObject(mobileId)
	end

end
function PetWindow.Update(timePassed)
end

function PetWindow.ButtonRotation()
	local showName = "PetWindowShowView"
	local hideName = "PetWindowHideView"
		
	if PetWindow.CloseLeft then
		WindowSetShowing(showName .. "HideButtonR", false)
		WindowSetShowing(showName .. "HideButton", true)
		WindowSetShowing(hideName .. "ShowButtonR", false)
		WindowSetShowing(hideName .. "ShowButton", true)
		WindowClearAnchors(hideName .. "Name")
		WindowAddAnchor(hideName .. "Name", "bottomleft", hideName, "topleft", 10, -20)
	else
		WindowSetShowing(showName .. "HideButtonR", true)
		WindowSetShowing(showName .. "HideButton", false)
		WindowSetShowing(hideName .. "ShowButtonR", true)
		WindowSetShowing(hideName .. "ShowButton", false)
		WindowClearAnchors(hideName .. "Name")
		WindowAddAnchor(hideName .. "Name", "bottomright", hideName, "topright", 0, -20)
	end
end

function PetWindow.UpdatePet()

	if(PetWindow.PetWindowHidden)then	
		return
	end
	local windowName = "PetWindow"
	local titleName = windowName.."ShowViewName"
	LabelSetText(titleName, GetStringFromTid(PetWindow.tid.PET) .. L" [" .. WindowData.PlayerStatus["Followers"] .. L"/" .. WindowData.PlayerStatus["MaxFollowers"] .. L"]" )
	if(WindowData.Pets.PetId ~= nil ) then	
		local petSize = table.getn(WindowData.Pets.PetId)
		if (petSize > 0) then
			PetWindow.SortedPet = {} 
			-- Update current pets
			for numPet = 1, petSize do
				local mobileId = WindowData.Pets.PetId[numPet]
				MobilesOnScreen.ReversePet[mobileId] = true
				PetWindow.SortedPet[numPet] = mobileId				
			end
			-- Cleanup old leftover pets
			for mobId,v in pairs(MobilesOnScreen.ReversePet) do
				local found = false
				for num,mob in pairs(PetWindow.SortedPet) do
					if mob == mobId then
						found = true
						break
					end
				end
				if not found and mobId ~= nil then					
					MobileHealthBar.CloseWindowByMobileId(mobId)					
					MobilesOnScreen.ReversePet[mobId] = nil
				end
			end
		else
			for key, value in pairs(MobilesOnScreen.ReversePet) do
				if key ~= nil then					
					MobileHealthBar.CloseWindowByMobileId(key)				
				end
			end
			MobilesOnScreen.ReversePet = {}
		end		
		PetWindow.UpdateAnchors()
	end
end

function PetWindow.ShowPetToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1154858))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	WindowSetAlpha(SystemData.ActiveWindow.name,1)
end

function PetWindow.ShowPetToolTipEnd()
	WindowSetAlpha(SystemData.ActiveWindow.name,0.5)
end

function PetWindow.HidePetToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,GetStringFromTid(1154859))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	WindowSetAlpha(SystemData.ActiveWindow.name,1)
end

function PetWindow.HidePetToolTipEnd()
	WindowSetAlpha(SystemData.ActiveWindow.name,0.5)
end

function PetWindow.UpdateAnchors()
	if (Interface.TimeSinceLogin < 1) then
		return
	end
	
	if (PetWindow.PetWindowHidden) then
		return
	end	
	local visible = 0	
	local petList = {}
	for key, mobileId in pairsByKeys(PetWindow.SortedPet) do	
		if (mobileId == nil or MobileHealthBar.Handled[mobileId] == true) then			
			continue
		end
		if WindowData.MountedObjId == mobileId then
			MobileHealthBar.CloseWindowByMobileId(mobileId)	
			continue
		end
		if(WindowData.MobileName[mobileId] == nil) then
			continue
		end		
		RegisterWindowData(WindowData.MobileName.Type, mobileId)
		local windowName = "MobileHealthBar_"..mobileId		
		if (not DoesWindowNameExist(windowName)) then
				MobileHealthBar.Forced = true
				MobileHealthBar.CreateHealthBar(mobileId)				
				MobileHealthBar.Forced = nil
		end
		table.insert(petList,mobileId)					
	end

	MobilesOnScreen.HandleAnchorsForCategory(visible, petList, 5, "PetWindow")
end

function PetWindow.OnMouseDrag()

	if ( not PetWindow.Locked) then
		SnapUtils.StartWindowSnap("PetWindow")
		WindowSetMoving("PetWindow",true)
	else
		WindowSetMoving("PetWindow",false)
	end
end

function PetWindow.HidePet()
	local windowName = "PetWindow"
	local showName = windowName.."ShowView"
	local hideName = windowName.."HideView"
	
	local newWindowPosX, newWindowPosY = WindowGetScreenPosition(windowName)
    if(newWindowPosX < 0) then
		WindowUtils.CopyScreenPosition(windowName,windowName,newWindowPosX,0)
    end
	WindowSetAlpha(hideName .. "ShowButton",0.5)
	WindowSetAlpha(hideName .. "ShowButtonR",0.5)
	
	WindowSetShowing(showName, false)
	WindowSetShowing(hideName, true)
	PetWindow.PetWindowHidden = true	
	SnapUtils.SnappableWindows[showName] = nil
	local petSize = table.getn(WindowData.Pets.PetId)
	for numPet = 1, petSize do
		local mobileId = WindowData.Pets.PetId[numPet]
		if(not MobileHealthBar.Handled[mobileId]) then
			if (MobileHealthBar.hasWindow[mobileId]) then				
				MobileHealthBar.CloseWindowByMobileId(mobileId)				
			end
		end
	end
	
	Interface.SaveBoolean( "PetWindowHidden", true )
	PetWindow.ButtonRotation()
	
end

function PetWindow.ShowPet()
	local windowName = "PetWindow"
	local showName = windowName.."ShowView"
	local hideName = windowName.."HideView"
		
	WindowSetAlpha(showName .. "HideButton",0.5)
	WindowSetAlpha(showName .. "HideButtonR",0.5)
	WindowSetShowing(showName, true)
	WindowSetShowing(hideName, false)
	
	SnapUtils.SnappableWindows[showName] = true
	
	PetWindow.PetWindowHidden = false

	Interface.SaveBoolean( "PetWindowHidden", false )

	PetWindow.UpdatePet()
	PetWindow.ButtonRotation()
end






