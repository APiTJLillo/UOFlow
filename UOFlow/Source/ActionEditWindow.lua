
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ActionEditWindow = {}

ActionEditWindow.CurEditItem = nil
ActionEditWindow.CurEditMacroItem = nil
ActionEditWindow.CurRequestInfoItem = nil
ActionEditWindow.CurActionId = nil

ActionEditWindow.TID_OK = 3000093
ActionEditWindow.TID_ADDEQUIPPED = 1114891

ActionEditWindow.Equip = {}
ActionEditWindow.Equip.NumItemsCreated = 0
ActionEditWindow.Equip.RegisteredObjects = {}

ActionEditWindow.ArmDisarmMaxLength = 4

ActionEditWindow.UnEquip = {}
ActionEditWindow.UnEquip.Slots = {}
ActionEditWindow.UnEquip.Slots[1] = { slot = EquipmentData.EQPOS_HEAD, x = 0, y = 0, texture = "slot_1" }
ActionEditWindow.UnEquip.Slots[2] = { slot = EquipmentData.EQPOS_NECK, x = 0, y = 0, texture = "slot_2"}
ActionEditWindow.UnEquip.Slots[3] = { slot = EquipmentData.EQPOS_ARMS, x = 0, y = 0, texture = "slot_3"}
ActionEditWindow.UnEquip.Slots[4] = { slot = EquipmentData.EQPOS_RIGHTHAND, x = 0, y = 0, texture = "slot_4"}
ActionEditWindow.UnEquip.Slots[5] = { slot = EquipmentData.EQPOS_FINGER1, x = 0, y = 0, texture = "slot_5"}
ActionEditWindow.UnEquip.Slots[6] = { slot = EquipmentData.EQPOS_LEGS, x = 0, y = 0, texture = "slot_6"}
ActionEditWindow.UnEquip.Slots[7] = { slot = EquipmentData.EQPOS_EARS, x = 0, y = 0, texture = "slot_7"}
ActionEditWindow.UnEquip.Slots[8] = { slot = EquipmentData.EQPOS_CHEST,  x = 0, y = 0, texture = "slot_8"}
ActionEditWindow.UnEquip.Slots[9] = { slot = EquipmentData.EQPOS_LWRIST, x = 0, y = 0, texture = "slot_9"}
ActionEditWindow.UnEquip.Slots[10] = { slot = EquipmentData.EQPOS_LEFTHAND, x = 0, y = 0, texture = "slot_10"}
ActionEditWindow.UnEquip.Slots[11] = { slot = EquipmentData.EQPOS_HANDS, x = 0, y = 0, texture = "slot_11" }
ActionEditWindow.UnEquip.Slots[12] = { slot = EquipmentData.EQPOS_TALISMAN, x = 0, y = 0, texture = "slot_12_edit" }
ActionEditWindow.UnEquip.Slots[13] = { slot = EquipmentData.EQPOS_FEET, x = 0, y = 0, texture = "slot_13" }
ActionEditWindow.UnEquip.Slots[14] = { slot = EquipmentData.EQPOS_TORSO, x = 0, y = 0, texture = "slot_14"  }
ActionEditWindow.UnEquip.Slots[15] = { slot = EquipmentData.EQPOS_WAIST, x = 0, y = 0 , texture = "slot_15" }
ActionEditWindow.UnEquip.Slots[16] = { slot = EquipmentData.EQPOS_ABOVECHEST, x = 0, y = 0, texture = "slot_16"  }
ActionEditWindow.UnEquip.Slots[17] = { slot = EquipmentData.EQPOS_CAPE, x = 0, y = 0, texture = "slot_17"  }
ActionEditWindow.UnEquip.Slots[18] = { slot = EquipmentData.EQPOS_DRESS, x = 0, y = 0, texture = "slot_18"  }
ActionEditWindow.UnEquip.Slots[19] = { slot = EquipmentData.EQPOS_SKIRT, x = 0, y = 0, texture = "slot_19"  }

ActionEditWindow.UnEquip.selected = {}


ActionEditWindow.ResourceRegisteredObject = 0

ActionEditWindow.ResourceType = {}
ActionEditWindow.ResourceType[1] = { resourceType = SystemData.UserAction.ERESOURCE_ORE, tid = 1079434 }
ActionEditWindow.ResourceType[2] = { resourceType = SystemData.UserAction.ERESOURCE_SAND, tid = 1044625 }
ActionEditWindow.ResourceType[3] = { resourceType = SystemData.UserAction.ERESOURCE_WOOD, tid = 1079435 }
ActionEditWindow.ResourceType[4] = { resourceType = SystemData.UserAction.ERESOURCE_GRAVE, tid = 1079436 }
ActionEditWindow.ResourceType[5] = { resourceType = SystemData.UserAction.ERESOURCE_RED_MUSHROOM, tid = 1079437 }
ActionEditWindow.ResourceType[6] = { resourceType = SystemData.UserAction.ERESOURCE_WATER, tid = 1115912 }
ActionEditWindow.ResourceType[7] = { resourceType = SystemData.UserAction.ERESOURCE_LAVA, tid = 1153112 }


ActionEditWindow.ResourceCategory = {}
--This category is for the "bladed" script attach chopping wood and getting red mushrooms
ActionEditWindow.ResourceCategory[1] = { 3, 5 }
--This category is for the "mining" script used for mining ore, sand and graves
ActionEditWindow.ResourceCategory[2] = { 1, 2, 4 }
ActionEditWindow.RESOURCE_TID = 1079438 --Choose a resource
--This category is for the "fishing" script used for water and lava
ActionEditWindow.ResourceCategory[3] = { 6, 7}
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function ActionEditWindow.Initialize()
	windowName = SystemData.ActiveWindow.name
		
	ButtonSetText(windowName.."OKButton",GetStringFromTid(ActionEditWindow.TID_OK))
	
	if( windowName == "ActionEditEquip" ) then
		WindowRegisterEventHandler("ActionEditEquip", WindowData.ObjectInfo.Event, "ActionEditWindow.EquipUpdateObject")
		ButtonSetText(windowName.."AddEquippedButton",GetStringFromTid(ActionEditWindow.TID_ADDEQUIPPED))
		ButtonSetText(windowName.."ClearButton",GetStringFromTid(1154967))
	end
	
	if ( windowName == "ActionEditUnEquip" ) then
		ActionEditWindow.CreateUnequipSlots(windowName)
	end
	
	if( windowName == "ActionEditArmDisarm" ) then
		ActionEditWindow.CreateArmDisarmSlots(windowName)
	end
	
	if( windowName == "ActionEditTargetByResource" ) then
		WindowSetShowing(windowName.."ResourceButton", false)
		WindowSetShowing(windowName.."ResourceLabel", false)
		WindowSetShowing(windowName.."ResourceCombo", false)
		LabelSetText(windowName.."ResourceLabel", GetStringFromTid(ActionEditWindow.RESOURCE_TID ) )
		UOBuildTableFromCSV("Data/GameData/resourcetype.csv", "ResourceTypeDataCSV")
		WindowRegisterEventHandler("ActionEditTargetByResource", WindowData.ObjectInfo.Event, "ActionEditWindow.TargetByResourceUpdateObject")
	end

end

function ActionEditWindow.Shutdown()
	UOUnloadCSVTable("ResourceTypeDataCSV")
end

function ActionEditWindow.UpdateTextEdit(editWindow, hotbarId, itemIndex, subIndex, actionId)
	local speechText = UserActionSpeechGetText(hotbarId, itemIndex, subIndex)	
	TextEditBoxSetText(editWindow.."Entry",speechText)
	WindowAssignFocus(editWindow.."Entry",true)
end

function ActionEditWindow.UpdateSliderEdit(editWindow, hotbarId, itemIndex, subIndex)
	local type

	if( ActionEditWindow.CurEditMacroItem ~= nil and ActionEditWindow.CurEditMacroItem.windowName == editWindow ) then
		type = ActionEditWindow.CurEditMacroItem.type
	else
		type = ActionEditWindow.CurEditItem.type
	end
	
	local actionData = ActionsWindow.GetActionDataForType(type)
	
	local delayValue = UserActionDelayGetDelay(hotbarId, itemIndex, subIndex)
	local sliderValue = (delayValue / (actionData.sliderMax - actionData.sliderMin)) + actionData.sliderMin
	SliderBarSetCurrentPosition(editWindow.."Slider",sliderValue)
	LabelSetText(editWindow.."Value",L""..wstring.format(L"%.1f",delayValue))
end

function ActionEditWindow.OpenEditWindow(actionType,anchorWindow,hotbarId,itemIndex,subIndex,actionId)
	-- subIndex default parameter is 0
	if( subIndex == nil ) then
		subIndex = 0
	end
	ActionEditWindow.CurActionId = actionId
	local actionData = ActionsWindow.GetActionDataForType(actionType)
	local actionId = UserActionGetId(hotbarId,itemIndex,subIndex)
	
	if actionId then
		if (actionId > 5000 ) then
			actionData = ActionsWindow.GetActionDataForID(actionId)
		end
	end

	--Debug.Print("ActionEditWindow.OpenEditWindow: "..tostring(actionType).." subIndex: "..tostring(subIndex).." actionData: "..tostring(actionData))
	
	-- if this action type has an edit window show it
	if( actionData ~= nil and actionData.editWindow ~= nil ) then
		local windowName = "ActionEdit"..actionData.editWindow
		
		-- if there is no sub index, this action is not within a macro
		if( subIndex == 0 ) then
			if( ActionEditWindow.CurEditItem ~= nil ) then
				WindowSetShowing(ActionEditWindow.CurEditItem.windowName,false)
			end
			
			--Debug.Print( "ActionEditWindow.OpenEditWindow() calling WindowSetShowing( "..tostring( windowName ).." )" )
			WindowSetShowing(windowName,true)
			ActionEditWindow.CurEditItem = 
			{
				windowName = windowName,
				hotbarId = hotbarId,
				itemIndex = itemIndex,
				type = actionType
			}
		-- otherwise this is a macro action so open it in a sub window
		else
			if( ActionEditWindow.CurEditMacroItem ~= nil ) then
				WindowSetShowing(ActionEditWindow.CurEditMacroItem.windowName,false)
			end
			WindowSetShowing(windowName,true)
			ActionEditWindow.CurEditMacroItem =
			{
				windowName = windowName,
				hotbarId = hotbarId,
				itemIndex = itemIndex,				
				subIndex = subIndex,
				type = actionType
			}
		end
		
		if( actionData.hideOK ~= nil and actionData.hideOK == true ) then
			WindowSetShowing(windowName.."OKButton", false)
		else
			WindowSetShowing(windowName.."OKButton", true)
		end

		-- set the parameter info label
		if( actionData.paramInfoTid ~= nil ) then
			LabelSetText(windowName.."ParamInfo",GetStringFromTid(actionData.paramInfoTid))
		elseif( actionData.paramInfoText ~= nil ) then
			LabelSetText(windowName.."ParamInfo",actionData.paramInfoText)
		end		
		
		-- anchor it to the window passed in
		if( anchorWindow ~= nil and windowName ~= "ActionEditMacro" ) then
		    WindowClearAnchors(windowName)
		    WindowAddAnchor(windowName,"topleft",anchorWindow,"bottomleft",0,-10)		
		end
		
		--Debug.Print( "ActionEditWindow.OpenEditWindow HotBarId: "..hotbarId.." itemIndex: "..itemIndex.." subIndex: "..subIndex.." actioId: " .. tostring(actionId))
		-- set up edit window
		if( UserActionIsSpeechType(hotbarId, itemIndex, subIndex) == true ) then
			ActionEditWindow.UpdateTextEdit(windowName, hotbarId, itemIndex, subIndex, actionId)
		elseif( actionType == SystemData.UserAction.TYPE_DELAY ) then
			local param = {HotbarId=hotbarId, ItemIndex=itemIndex, SubIndex=subIndex }
			local rdata = {title=GetStringFromTid(3002103), subtitle=GetStringFromTid(1155371), callfunction=ActionEditWindow.CustomDelay, id=param}
			RenameWindow.Create(rdata)
			WindowSetShowing(windowName,false)
			--ActionEditWindow.UpdateSliderEdit(windowName, hotbarId, itemIndex, subIndex)
		elseif( actionType == SystemData.UserAction.TYPE_MACRO ) then
			MacroEditWindow.UpdateMacroEdit(windowName, hotbarId, itemIndex)
		elseif( actionType == SystemData.UserAction.TYPE_EQUIP_ITEMS ) then
			ActionEditWindow.UpdateEquipItemEdit(windowName, hotbarId, itemIndex, subIndex)
		elseif( actionType == SystemData.UserAction.TYPE_UNEQUIP_ITEMS ) then
			ActionEditWindow.UpdateUnequipEdit(windowName, hotbarId, itemIndex, subIndex)
		elseif( actionType == SystemData.UserAction.TYPE_ARM_DISARM ) then
			ActionEditWindow.UpdateArmDisarmEdit(windowName, hotbarId, itemIndex, subIndex)
		elseif( actionType == SystemData.UserAction.TYPE_TARGET_BY_RESOURCE ) then
			ActionEditWindow.UpdateTargetByResourceEdit(windowName, hotbarId, itemIndex, subIndex)
		elseif( actionType == SystemData.UserAction.TYPE_TARGET_BY_OBJECT_ID ) then
			ActionEditWindow.UpdateTargetByObjectId(windowName, hotbarId, itemIndex, subIndex)
		end
	end	
end

function ActionEditWindow.CustomDelay(param, text)
	local delayValue = tonumber(text) or 0
	if delayValue and delayValue > 0 then
		UserActionDelaySetDelay(param.HotbarId, param.ItemIndex, param.SubIndex, delayValue)
	end
end

function ActionEditWindow.TextEditOK()
	local windowName = WindowUtils.GetActiveDialog()

	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex
	local subIndex = 0
	local actionId = UserActionGetId(hotbarId,itemIndex,subIndex)
	
	-- if this is a sub window get the subindex and clear the table
	if( ActionEditWindow.CurEditMacroItem ~= nil and ActionEditWindow.CurEditMacroItem.windowName == windowName ) then
		subIndex = ActionEditWindow.CurEditMacroItem.subIndex
		ActionEditWindow.CurEditMacroItem = nil
	-- otherwise its the main window so clear that table
	else
		ActionEditWindow.CurEditItem = nil
	end

	local speechText = ActionEditTextEntry.Text

	UserActionSpeechSetText(hotbarId, itemIndex, subIndex, speechText)
	
	WindowSetShowing(windowName,false)	
end

function ActionEditWindow.SliderEditOK()
	local windowName = WindowUtils.GetActiveDialog()

	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex
	local subIndex = 0
	local type
	
	-- if this is a sub window get the subindex and clear the table
	if( ActionEditWindow.CurEditMacroItem ~= nil and ActionEditWindow.CurEditMacroItem.windowName == windowName ) then
		subIndex = ActionEditWindow.CurEditMacroItem.subIndex
		type = ActionEditWindow.CurEditMacroItem.type
		ActionEditWindow.CurEditMacroItem = nil
	-- otherwise its the main window so clear that table
	else
		type = ActionEditWindow.CurEditItem.type
		ActionEditWindow.CurEditItem = nil
	end
	
	local actionData = ActionsWindow.GetActionDataForType(type)
	
	local sliderValue = SliderBarGetCurrentPosition(windowName.."Slider")
	local delayValue = (sliderValue - actionData.sliderMin) * (actionData.sliderMax - actionData.sliderMin)
	
	--Debug.Print("Set Delay: "..tostring(hotbarId)..", "..tostring(itemIndex)..", "..tostring(subIndex)..", delay: "..tostring(delayValue))
	
	UserActionDelaySetDelay(hotbarId, itemIndex, subIndex, delayValue)
	
	WindowSetShowing(windowName,false)
end

function ActionEditWindow.SliderUpdate()
	local type
	local windowName = WindowUtils.GetActiveDialog()
	
	if( ActionEditWindow.CurEditMacroItem ~= nil and ActionEditWindow.CurEditMacroItem.windowName == windowName ) then
		type = ActionEditWindow.CurEditMacroItem.type
	else
		type = ActionEditWindow.CurEditItem.type
	end

	local actionData = ActionsWindow.GetActionDataForType(type)
	
	local sliderValue = SliderBarGetCurrentPosition(windowName.."Slider")
	local delayValue = (sliderValue - actionData.sliderMin) * (actionData.sliderMax - actionData.sliderMin)
	
	LabelSetText(windowName.."Value",L""..wstring.format(L"%.1f",delayValue))
end

function ActionEditWindow.UpdateEquipItemEdit(windowName, hotbarId, itemIndex, subIndex)
	for i = 1, ActionEditWindow.Equip.NumItemsCreated do
		local equipWindowName = windowName.."ActionsScrollChildItem"..i
		WindowClearAnchors(equipWindowName)
		WindowSetShowing(equipWindowName,false)
	end
	
	--Unregister objectId data
	ActionEditWindow.UnregisterEquipItems(windowName)
	
	local numItems = UserActionEquipItemsGetNumItems(hotbarId, itemIndex, subIndex)
	if(numItems ~= nil and numItems > 0 ) then
		for i = 1, numItems do
			local objectId = UserActionEquipItemsGetItem(hotbarId, itemIndex, subIndex, i-1)
			if((objectId ~= nil) and (objectId ~= -1)) then
				local equipWindowName = windowName.."ActionsScrollChildItem"..i
				if( i > ActionEditWindow.Equip.NumItemsCreated ) then
				
					CreateWindowFromTemplate( equipWindowName, "EquipButtonDef", windowName.."ActionsScrollChild" )
					WindowSetId( equipWindowName, i )
					ActionEditWindow.Equip.NumItemsCreated = ActionEditWindow.Equip.NumItemsCreated + 1
				end
				
				--Stored the registered objects
				RegisterWindowData(WindowData.ObjectInfo.Type, objectId)
				ActionEditWindow.Equip.RegisteredObjects[i] = objectId
				
				--Update the icon window with the image of the object
				ActionEditWindow.UpdateEquipIcon(equipWindowName, objectId)	
				-- reanchor window
				if (i==1) then
					WindowAddAnchor( equipWindowName, "topleft", windowName.."ActionsScrollChild", "topleft", 0, 0)    
				else
					WindowAddAnchor( equipWindowName, "topright", windowName.."ActionsScrollChildItem"..(i-1), "topleft", 0, 0)
				end
				
				WindowSetShowing(equipWindowName,true)
			end
		end
		
		if( numItems <= 5 ) then
			HorizontalScrollWindowSetOffset(windowName.."Actions", 0)
		end
	end
	
	-- add the empty button to the end
	local emptyButtonName = windowName.."ActionsScrollChildEmptyButton"
	WindowClearAnchors(emptyButtonName)
	if( not numItems or numItems == 0 ) then
		WindowAddAnchor(emptyButtonName, "topleft", windowName.."ActionsScrollChild", "topleft", 0, 0)    
	else
		WindowAddAnchor(emptyButtonName, "right", windowName.."ActionsScrollChildItem"..numItems, "left", 0, 0)
	end
		
	HorizontalScrollWindowUpdateScrollRect(windowName.."Actions")
end

function ActionEditWindow.EquipUpdateObject()
	local windowName = SystemData.ActiveWindow.name

	local updateId = WindowData.UpdateInstanceId
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(windowName)
	
	if( hotbarId ~= nil and itemIndex ~= nil and subIndex ~= nil ) then
	    local numItems = UserActionEquipItemsGetNumItems(hotbarId, itemIndex, subIndex)
	    local index = -1
    	
	    if( numItems ~= nil ) then
		    for i= 1, numItems do
			    if ( ActionEditWindow.Equip.RegisteredObjects[i] == updateId ) then
				    index = i
				    break
			    end
		    end
		    
		    if( index >= 1 ) then
		        local objectId = UserActionEquipItemsGetItem(hotbarId, itemIndex, subIndex, index-1)
		        if((objectId ~= nil) and (objectId ~= -1) and (updateId == objectId) ) then
			        local equipWindowName = windowName.."ActionsScrollChildItem"..index
			        ActionEditWindow.UpdateEquipIcon(equipWindowName, objectId)
		        end
		    end
	    end
	end
end

function ActionEditWindow.GetActionInfo(windowName)
    if( ActionEditWindow.CurEditItem ~= nil ) then
	    local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	    local itemIndex = ActionEditWindow.CurEditItem.itemIndex
	    local subIndex = 0 
          
	    -- if this is a sub window get the subindex and clear the table 
	    if( ActionEditWindow.CurEditMacroItem ~= nil and ActionEditWindow.CurEditMacroItem.windowName == windowName ) then 
		    subIndex = ActionEditWindow.CurEditMacroItem.subIndex
	    end
	    return hotbarId, itemIndex, subIndex
	end
end

function ActionEditWindow.EquipLButtonUp()
	local windowName = SystemData.ActiveWindow.name
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	
	if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then	
	    local itemId = SystemData.DragItem.itemId
	    local itemType = SystemData.DragItem.itemType

	    local bSuccess = DragSlotDropObjectToSource()
	
		if( bSuccess ) then		
		    local itemAdd = UserActionEquipItemsAddItem(hotbarId, itemIndex, subIndex, itemId, itemType)
		    if(itemAdd ) then
			    ActionEditWindow.UpdateEquipItemEdit(parent, hotbarId, itemIndex, subIndex)
		    end
		end
	end
end

function ActionEditWindow.UpdateEquipIcon(windowName, objectId)
	if((objectId ~= nil) and (objectId ~= -1) and (windowName ~= nil) ) then
		local elementIcon = windowName.."SquareIcon"
		local item = WindowData.ObjectInfo[objectId]
		EquipmentData.UpdateItemIcon(elementIcon, item)
	end
end

function ActionEditWindow.EquipRButtonUp()
	--Display Clear Item context menu
	--Debug.Print(" ActionEditWindow.EquipRButtonUp()")
	
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	local slot = WindowGetId(SystemData.ActiveWindow.name)
	local param = {HotbarId = hotbarId, ItemIndex = itemIndex , SubIndex = subIndex, WindowName = parent, Slot = slot}	
	
	--Debug.Print("hotbarId: "..param.HotbarId.." ItemIndex: "..param.ItemIndex.." subIndex: "..param.SubIndex.."windowName: "..param.WindowName.."Slot: "..slot)
	ContextMenu.CreateLuaContextMenuItem(HotbarSystem.TID_CLEAR_ITEM ,0, HotbarSystem.ContextReturnCodes.CLEAR_ITEM,param)
	
	ContextMenu.ActivateLuaContextMenu(ActionEditWindow.Equip.ContextMenuCallback)
end

function ActionEditWindow.Equip.ContextMenuCallback(returnCode,param)
	if( param ~= nil ) then
		if( returnCode == HotbarSystem.ContextReturnCodes.CLEAR_ITEM ) then
			local objectId = ActionEditWindow.Equip.RegisteredObjects[param.Slot]
			if( objectId ~= nil ) then
				--Remove Item from the equipment slot
				--Debug.Print("HotbarId: "..param.HotbarId.." ItemIndex: "..param.ItemIndex.." subIndex: "..param.SubIndex.."objectId: "..objectId)
				UserActionEquipItemsRemoveItem(param.HotbarId, param.ItemIndex, param.SubIndex, objectId)
				--Unregister equip item data when the item gets removed from the equip macro slot
				UnregisterWindowData(WindowData.ObjectInfo.Type,ActionEditWindow.Equip.RegisteredObjects[param.Slot])
				ActionEditWindow.Equip.RegisteredObjects[param.Slot] = nil
				ActionEditWindow.UpdateEquipItemEdit(param.WindowName, param.HotbarId, param.ItemIndex, param.SubIndex)
			end
		end
	end	
	
end

function ActionEditWindow.EquipMouseOver()
	--Debug.Print(" ActionEditWindow.EquipMouseOver()")
	local buttonName = SystemData.ActiveWindow.name
	local text = GetStringFromTid(MacroEditWindow.TID_MACRO_DRAG_EQUIP_TOOLTIP)
	Tooltips.CreateTextOnlyTooltip(buttonName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function ActionEditWindow.UnregisterEquipItems()
	local windowName = WindowUtils.GetActiveDialog()
	local tableSize = table.getn(ActionEditWindow.Equip.RegisteredObjects)
	for i = 1, tableSize do
		if( ActionEditWindow.Equip.RegisteredObjects[i] ~= nil ) then
			UnregisterWindowData(WindowData.ObjectInfo.Type,ActionEditWindow.Equip.RegisteredObjects[i])
			ActionEditWindow.Equip.RegisteredObjects[i] = nil
			local slotWin = windowName.."ActionsScrollChildItem"..i
			DynamicImageSetTexture(slotWin .. "SquareIcon", "", 0, 0 ) 
		end
	end
end

function ActionEditWindow.EquipItemOK()
	local windowName = WindowUtils.GetActiveDialog()
	--Unregister equip object id data
	ActionEditWindow.UnregisterEquipItems()
	WindowSetShowing(windowName,false)	
end

function ActionEditWindow.EquipClearEquipped()
	local parent = "ActionEditEquip"
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	
	
	local tableSize = table.getn(ActionEditWindow.Equip.RegisteredObjects)
	for i = 1, tableSize do
		local objectId = ActionEditWindow.Equip.RegisteredObjects[i]
		if( ActionEditWindow.Equip.RegisteredObjects[i] ~= nil ) then
			UserActionEquipItemsRemoveItem(hotbarId, itemIndex, subIndex, objectId)
			UnregisterWindowData(WindowData.ObjectInfo.Type,ActionEditWindow.Equip.RegisteredObjects[i])
			ActionEditWindow.Equip.RegisteredObjects[i] = nil
			local windowName = parent.."ActionsScrollChildItem"..i
			DynamicImageSetTexture(windowName .. "SquareIcon", "", 0, 0 ) 
		end
	end
	ActionEditWindow.UpdateEquipItemEdit(parent, hotbarId, itemIndex, subIndex)
end

function ActionEditWindow.EquipItemAddEquipped()
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)

	UserActionEquipItemsAddEquippedItems(hotbarId, itemIndex, subIndex)
	ActionEditWindow.UpdateEquipItemEdit(parent, hotbarId, itemIndex, subIndex)
end

--Creates all the unequip position slots when client launches
function ActionEditWindow.CreateUnequipSlots(windowName)
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		local unequipWindowName = windowName.."ActionsScrollChildSlot"..i
		CreateWindowFromTemplate( unequipWindowName, "UnequipButtonDef", windowName.."ActionsScrollChild" )
		WindowSetId( unequipWindowName, i )
		WindowSetId( unequipWindowName.."Button", i )
		ButtonSetStayDownFlag(unequipWindowName.."Button", true)
		local elementIcon = unequipWindowName.."SquareIcon"
		
		local texture = ActionEditWindow.UnEquip.Slots[i].texture
		local x = ActionEditWindow.UnEquip.Slots[i].x
		local y = ActionEditWindow.UnEquip.Slots[i].y
		
		DynamicImageSetTexture(elementIcon, texture, x, y )
		
		if (i==1) then
			WindowAddAnchor( unequipWindowName, "topleft", windowName.."ActionsScrollChild", "topleft", 0, 0)    
		else
			WindowAddAnchor( unequipWindowName, "bottomleft", windowName.."ActionsScrollChildSlot"..(i-1), "topleft", 0, 0)
		end
	end
end

function ActionEditWindow.UpdateUnequipEdit(windowName, hotbarId, itemIndex, subIndex)
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		local slotFound = UserActionFindSlot(hotbarId, itemIndex, subIndex, ActionEditWindow.UnEquip.Slots[i].slot)
		local buttonWindowName = windowName.."ActionsScrollChildSlot"..i.."Button"
		
		if( slotFound == true ) then
			ActionEditWindow.UnEquip.selected[i] = true	
		else
			ActionEditWindow.UnEquip.selected[i] = false
		end
		ButtonSetPressedFlag( buttonWindowName, ActionEditWindow.UnEquip.selected[i] )
	end
	
	WindowSetShowing(windowName, true)
end

function ActionEditWindow.UnequipPosSelected()
	local type = WindowGetId(SystemData.ActiveWindow.name) 
	local parent = WindowUtils.GetActiveDialog()
	
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	if((ActionEditWindow.UnEquip.selected[type] == nil) or (ActionEditWindow.UnEquip.selected[type] == false)) then
		ActionEditWindow.UnEquip.selected[type] = true
		UserActionAddSlot(hotbarId, itemIndex, subIndex, ActionEditWindow.UnEquip.Slots[type].slot)
	else
		ActionEditWindow.UnEquip.selected[type] = false
		UserActionRemoveSlot(hotbarId, itemIndex, subIndex, ActionEditWindow.UnEquip.Slots[type].slot)
	end
	
	ButtonSetPressedFlag( SystemData.ActiveWindow.name, ActionEditWindow.UnEquip.selected[type] )
end

function ActionEditWindow.UnEquipOK()
	local windowName = WindowUtils.GetActiveDialog()
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		ButtonSetPressedFlag( windowName.."ActionsScrollChildSlot"..i.."Button", false )
		ActionEditWindow.UnEquip.selected[i] = nil
	end
	WindowSetShowing(windowName,false)	
end

--Creates all the arm/disarm slot positions when client launches
function ActionEditWindow.CreateArmDisarmSlots(windowName)
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		local armWindowName = windowName.."Slot"..i
		CreateWindowFromTemplate( armWindowName, "ArmDisarmButtonDef", windowName )
		WindowSetId( armWindowName, i )
		WindowSetId( armWindowName.."Button", i )
		ButtonSetStayDownFlag(armWindowName.."Button", true)
		local elementIcon = armWindowName.."SquareIcon"
		
		local texture = ActionEditWindow.UnEquip.Slots[i].texture
		local x = ActionEditWindow.UnEquip.Slots[i].x
		local y = ActionEditWindow.UnEquip.Slots[i].y
		
		DynamicImageSetTexture(elementIcon, texture, x, y )
		
		if (i==1) then
			WindowAddAnchor( armWindowName, "bottomleft", windowName.."ParamInfo", "topleft", 0, 10)    
		else
			local place = i % (ActionEditWindow.ArmDisarmMaxLength)
			--Need to anchor the icon on the next row since its greater then the max length of buff icons in one row
			if( place == 1) then
				WindowAddAnchor(armWindowName, "bottomleft", windowName.."Slot"..(i - ActionEditWindow.ArmDisarmMaxLength), "topleft", 0, 0)
			else
				WindowAddAnchor(armWindowName, "topright", windowName.."Slot"..(i-1), "topleft", 0 , 0)
			end
		end
		
	end
end

function ActionEditWindow.UpdateArmDisarmEdit(windowName, hotbarId, itemIndex, subIndex)
	local windowName = "ActionEditArmDisarm"
	local slotNumber = UserActionArmDisarmGetSlotNumber(hotbarId, itemIndex, subIndex)
	local slotIndex = 0
	local buttonWindowName
	
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		buttonWindowName = windowName.."Slot"..i.."Button"
		ButtonSetPressedFlag( buttonWindowName, false )
		
		if( ActionEditWindow.UnEquip.Slots[i].slot == slotNumber ) then
			slotIndex = i
		end
	end
	
	if( slotNumber ~= 0 ) then
		buttonWindowName = windowName.."Slot"..slotIndex.."Button"
		ButtonSetPressedFlag( buttonWindowName, true )
	end

	WindowSetShowing(windowName, true)
end

function ActionEditWindow.ArmDisarmSelectSlot()
	local windowName = "ActionEditArmDisarm"
	local buttonId = WindowGetId(SystemData.ActiveWindow.name)
	local slotNumber = ActionEditWindow.UnEquip.Slots[buttonId].slot
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	
	local buttonWindowName
	UserActionArmDisarmSelectSlot(hotbarId, itemIndex, subIndex, slotNumber)
	
	for i = 1, table.getn(ActionEditWindow.UnEquip.Slots) do
		buttonWindowName = windowName.."Slot"..i.."Button"
		ButtonSetPressedFlag( buttonWindowName, false )
	end
	
	buttonWindowName = windowName.."Slot"..buttonId.."Button"
	ButtonSetPressedFlag( buttonWindowName, true )	
end

function ActionEditWindow.ArmDisarmOK()
	local windowName = WindowUtils.GetActiveDialog()
	WindowSetShowing(windowName,false)
end

-- Target By Resource functions

function ActionEditWindow.TargetByResourceUpdateObject()
	local windowName = SystemData.ActiveWindow.name

	local updateId = WindowData.UpdateInstanceId
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(windowName)
	
	if( hotbarId ~= nil and itemIndex ~= nil and subIndex ~= nil ) then
	
	    local objectId = UserActionTargetByResourceGetUseObjectInstanceId( hotbarId, itemIndex, subIndex)
		if( objectId ~= nil and objectId ~= -1 and updateId == objectId) then
			ActionEditWindow.UpdateTargetByResourceIcon(windowName, objectId)
			local resourceCategory = UserActionTargetByResourceGetResourceCategory(hotbarId, itemIndex, subIndex)
			if(resourceCategory ~= nil and resourceCategory ~= 0) then
				local resourceType = UserActionTargetByResourceGetResourceType(hotbarId, itemIndex, subIndex)
				ActionEditWindow.TargetByResourceResetComboBox( windowName, resourceType, resourceCategory )
			end
		end
	end
end

function ActionEditWindow.UpdateTargetByResourceIcon(windowName, objectId)
	local resourceButtonName = windowName.."ResourceButton"
	local emptyButtonName = windowName.."EmptyButton"
	local elementIcon = resourceButtonName.."SquareIcon"
	
	if (objectId ~= 0) then		
		local item = WindowData.ObjectInfo[objectId]

		EquipmentData.UpdateItemIcon(elementIcon, item)
		WindowSetShowing(resourceButtonName,true)
		WindowSetShowing(emptyButtonName,false)
	end
end

function ActionEditWindow.UpdateTargetByResourceEdit(windowName, hotbarId, itemIndex, subIndex)
	--Unregister objectId data
	if( ActionEditWindow.ResourceRegisteredObject ~= 0) then
		UnregisterWindowData(WindowData.ObjectInfo.Type,ActionEditWindow.ResourceRegisteredObject)
	end
	
	local resourceButtonName = windowName.."ResourceButton"
	local emptyButtonName = windowName.."EmptyButton"
	local elementIcon = resourceButtonName.."SquareIcon"
		
	WindowSetShowing(emptyButtonName, true)
	WindowSetShowing(resourceButtonName, false)
		
	local objectId = UserActionTargetByResourceGetUseObjectInstanceId( hotbarId, itemIndex, subIndex)
		
	if( objectId ~= nil and objectId ~= -1 ) then
		RegisterWindowData(WindowData.ObjectInfo.Type, objectId)
		ActionEditWindow.ResourceRegisteredObject = objectId
		ActionEditWindow.UpdateTargetByResourceIcon(windowName, objectId)
		local resourceType = UserActionTargetByResourceGetResourceType( hotbarId, itemIndex, subIndex)
		local resourceCategory = UserActionTargetByResourceGetResourceCategory( hotbarId, itemIndex, subIndex)
		if( resourceType ~= nil and resourceCategory ~= nil ) then
			WindowSetShowing(windowName.."ResourceLabel", true)
			ActionEditWindow.TargetByResourceResetComboBox( windowName, resourceType, resourceCategory )
		end
	end
	
end

function ActionEditWindow.TargetByResourceLButtonUp()
	local windowName = SystemData.ActiveWindow.name
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	
	if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then	
	    local id = SystemData.DragItem.itemId
	    local objectType = SystemData.DragItem.itemType

		--check to see if the object player dropped into
		for i = 1, table.getn( WindowData.ResourceTypeDataCSV ) do
			-- HACKY IF STATEMENT CHECK BECAUSE CSV TABLE SEEMS TO CONTAIN NIL VALUES
			if( ( WindowData.ResourceTypeDataCSV[i].ObjectType == objectType ) ) then
			    local bSuccess = DragSlotDropObjectToSource()
			    if( bSuccess ) then
					local currentCategory  = WindowData.ResourceTypeDataCSV[i].Category
				    local resourceTypeNum = ActionEditWindow.ResourceCategory[currentCategory][1]
				    local defaultResource = ActionEditWindow.ResourceType[resourceTypeNum].resourceType
				    UserActionTargetByResourceSetUseObjectInstanceId(hotbarId, itemIndex, subIndex, id)
				    UserActionTargetByResourceSetResourceType(hotbarId, itemIndex, subIndex, defaultResource)
				    UserActionTargetByResourceSetResourceCategory(hotbarId, itemIndex, subIndex, currentCategory)
    				
				    ActionEditWindow.UpdateTargetByResourceEdit(parent, hotbarId, itemIndex, subIndex)
				end
				return
			end
		end
	end

end

function ActionEditWindow.TargetByResourceResetComboBox( windowName, resourceTypeSelected , currentCategory)
	local comboName = windowName.."ResourceCombo"
	--Clear combo box first
	ComboBoxClearMenuItems(comboName)
	
	WindowSetShowing(windowName.."ResourceLabel", false)
	WindowSetShowing(windowName.."ResourceCombo", false)
	
	local category = ActionEditWindow.ResourceCategory[currentCategory]
	
	if(category ~= nil) then
		local indexIter
		local resource
		WindowSetShowing(windowName.."ResourceLabel", true)
		WindowSetShowing(comboName, true)
		for indexIter, resource in pairs(category) do
			ComboBoxAddMenuItem( comboName, GetStringFromTid(ActionEditWindow.ResourceType[resource].tid))
			if( resourceTypeSelected == ActionEditWindow.ResourceType[resource].resourceType ) then
				ComboBoxSetSelectedMenuItem( comboName, indexIter)
			end
		end
		
	end
	
end

function ActionEditWindow.TargetByResourceMouseOver()
	local buttonName = SystemData.ActiveWindow.name
	local text = GetStringFromTid(MacroEditWindow.TID_MACRO_DRAG_TARGET_BY_RESOURCE_TOOLTIP)
	Tooltips.CreateTextOnlyTooltip(buttonName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function ActionEditWindow.TargetByResourceOK()
	local windowName = WindowUtils.GetActiveDialog()
	local comboName = windowName.."ResourceCombo"
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(windowName)
	
	local category = UserActionTargetByResourceGetResourceCategory(hotbarId, itemIndex, subIndex)
	if( category ~= 0) then
		local selectedItem = ComboBoxGetSelectedMenuItem( comboName )
		local resourceSelected = ActionEditWindow.ResourceCategory[category][selectedItem]
		local resourceType = ActionEditWindow.ResourceType[resourceSelected].resourceType
		
		UserActionTargetByResourceSetResourceType(hotbarId, itemIndex, subIndex, resourceType)
	end
	
	--Unregister object id data
	if( ActionEditWindow.ResourceRegisteredObject ~= 0) then
		UnregisterWindowData(WindowData.ObjectInfo.Type,ActionEditWindow.ResourceRegisteredObject)
	end
	WindowSetShowing(windowName,false)	
end

function ActionEditWindow.UpdateTargetByObjectId(windowName, hotbarId, itemIndex, subIndex)
	ActionEditWindow.CurRequestInfoItem =
	{
		windowName = windowName,
		hotbarId = hotbarId,
		itemIndex = itemIndex,				
		subIndex = subIndex,
	}

	RequestTargetInfo()
	
	WindowRegisterEventHandler("ActionEditTargetByObjectId", SystemData.Events.TARGET_SEND_ID_CLIENT, "ActionEditWindow.RequestTargetInfoReceived")
end

function ActionEditWindow.TargetByObjectIdOK()
	WindowUnregisterEventHandler("ActionEditTargetByObjectId", SystemData.Events.TARGET_SEND_ID_CLIENT)
	WindowSetShowing("ActionEditTargetByObjectId", false)
end

function ActionEditWindow.RequestTargetInfoReceived()
	local objectId = SystemData.RequestInfo.ObjectId
	
	if (objectId ~= 0 and ActionEditWindow.CurRequestInfoItem ~= nil) then
		UserActionSetTargetId(ActionEditWindow.CurRequestInfoItem.hotbarId, ActionEditWindow.CurRequestInfoItem.itemIndex, ActionEditWindow.CurRequestInfoItem.subIndex, objectId)
		UserActionSetTargetType(ActionEditWindow.CurRequestInfoItem.hotbarId, ActionEditWindow.CurRequestInfoItem.itemIndex, ActionEditWindow.CurRequestInfoItem.subIndex, SystemData.Hotbar.TargetType.TARGETTYPE_OBJECT_ID)
	end
	
	ActionEditWindow.TargetByObjectIdOK()
end