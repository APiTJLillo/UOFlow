
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

MacroEditWindow = {}

MacroEditWindow.TID_EDIT_MACRO = 1111854
MacroEditWindow.TID_REPEAT = 1079431 -- "Enable Repeating"
MacroEditWindow.TID_REPEAT_TIMES = 1079432 -- "Repeat this many times:"
MacroEditWindow.TID_MACRO_ICON_TOOLTIP = 1078507
MacroEditWindow.TID_MACRO_DRAG_TOOLTIP = 1078508
MacroEditWindow.TID_MACRO_DRAG_EQUIP_TOOLTIP = 1078617
MacroEditWindow.TID_MACRO_DRAG_TARGET_BY_RESOURCE_TOOLTIP = 1079429

MacroEditWindow.MACRO_SCROLLWINDOW_WIDTH = 310
MacroEditWindow.MACRO_ACTION_WIDTH = 50

MacroEditWindow.Macro = {}
MacroEditWindow.Macro.NumActionsCreated = 0

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function MacroEditWindow.Initialize()
	windowName = SystemData.ActiveWindow.name	
	ButtonSetText(windowName.."OKButton",GetStringFromTid(ActionEditWindow.TID_OK))
	WindowUtils.SetWindowTitle("ActionEditMacro", GetStringFromTid(MacroEditWindow.TID_EDIT_MACRO))
	Interface.OnCloseCallBack[windowName] = MacroEditWindow.MacroEditOK
end

function MacroEditWindow.Shutdown()
end

function MacroEditWindow.UpdateMacroActionList(editWindow, hotbarId, itemIndex)
	for i = 1, MacroEditWindow.Macro.NumActionsCreated do
		local actionWindowName = editWindow.."ActionsScrollChildItem"..i
		WindowClearAnchors(actionWindowName)
		WindowSetShowing(actionWindowName,false)
		HotbarSystem.ClearActionIcon(actionWindowName,hotbarId,itemIndex,i,true)
	end

	local numActions = UserActionMacroGetNumActions(hotbarId, itemIndex)
	for i = 1, numActions do
		local actionWindowName = editWindow.."ActionsScrollChildItem"..i
		if( i > MacroEditWindow.Macro.NumActionsCreated ) then
			CreateWindowFromTemplate( actionWindowName, "MacroActionDef", editWindow.."ActionsScrollChild" )
			WindowSetId( actionWindowName, i )
			WindowSetShowing(actionWindowName.."HotkeyBackground",false)
			
			MacroEditWindow.Macro.NumActionsCreated = MacroEditWindow.Macro.NumActionsCreated + 1
		end
		
		-- reanchor window
		if (i==1) then
         	WindowAddAnchor( actionWindowName, "topleft", editWindow.."ActionsScrollChild", "topleft", 0, 0)    
		else
        	WindowAddAnchor( actionWindowName, "topright", editWindow.."ActionsScrollChildItem"..(i-1), "topleft", 0, 0)
		end
		
		HotbarSystem.RegisterAction(actionWindowName, hotbarId, itemIndex, i)
		
		WindowSetShowing(actionWindowName,true)
		
		if( UserActionIsTargetModeCompat(hotbarId, itemIndex, i) ) then
			WindowSetShowing(actionWindowName.."Disabled", false)
			ButtonSetDisabledFlag(actionWindowName, false)
		else
			WindowSetShowing(actionWindowName.."Disabled", true)
			ButtonSetDisabledFlag(actionWindowName, true)
		end
	end
	
	-- add the empty button to the end
	local emptyButtonName = editWindow.."ActionsScrollChildEmptyButton"
	WindowClearAnchors(emptyButtonName)
	WindowSetId( emptyButtonName, numActions+1 )
	if( numActions == 0 ) then
		WindowAddAnchor(emptyButtonName, "topleft", editWindow.."ActionsScrollChild", "topleft", 0, 0)
	else
		WindowAddAnchor(emptyButtonName, "right", editWindow.."ActionsScrollChildItem"..numActions, "left", 0, 0)
	end
		
	HorizontalScrollWindowUpdateScrollRect(editWindow.."Actions")
	if( numActions < 7 ) then
		HorizontalScrollWindowSetOffset(editWindow.."Actions", 0)
	end
end

function MacroEditWindow.UpdateMacroEdit(editWindow, hotbarId, itemIndex)
	-- set some labels
	LabelSetText(editWindow.."RepeatToggleLabel", GetStringFromTid(MacroEditWindow.TID_REPEAT))
	LabelSetText(editWindow.."RepeatText", GetStringFromTid(MacroEditWindow.TID_REPEAT_TIMES))
	
	-- Update the scroll bars shown value
	local count = UserActionMacroGetRepeatCount(hotbarId,itemIndex)
	LabelSetText( editWindow.."RepeatVal", StringToWString(tostring(count)) )
	local position = ( count - 2 ) / 8.0
	SliderBarSetCurrentPosition( editWindow.."RepeatSliderBar", position )

	ButtonSetStayDownFlag( editWindow.."RepeatToggleButton", true )
	ButtonSetCheckButtonFlag( editWindow.."RepeatToggleButton", true )
	local bRepeat = UserActionMacroGetRepeatEnabled( hotbarId, itemIndex ) --ButtonGetPressedFlag( editWindow.."RepeatToggleButton")
	if bRepeat then
		ButtonSetPressedFlag( editWindow.."RepeatToggleButton", true )
	else
		ButtonSetPressedFlag( editWindow.."RepeatToggleButton", false )
	end	
	MacroEditWindow.FirstTimeHack = false
	
	-- macros are always subindex 0
	local macroName = UserActionMacroGetName(hotbarId, itemIndex)
	TextEditBoxSetText(editWindow.."NameEntry",macroName)
	
	local iconId = UserActionGetIconId(hotbarId, itemIndex,0)
	local texture, x, y = GetIconData(iconId)
	DynamicImageSetTexture( editWindow.."NameIcon", texture, x, y )
	
	local texture, x, y = GetIconData(iconId)
		
	DynamicImageSetTexture( editWindow.."NameIcon", texture, x, y )
	DynamicImageSetTexture( editWindow.."NameIconBG", MiniTexturePack.DB[MiniTexturePack.Current].texture .. "Icon", x, y )
	
	HorizontalScrollWindowSetOffset(editWindow.."Actions",0)
	
	MacroEditWindow.UpdateMacroActionList(editWindow, hotbarId, itemIndex)
end

function MacroEditWindow.UpdateTextEdit(editWindow, hotbarId, itemIndex, subIndex)
local speechText = UserActionSpeechGetText(hotbarId, itemIndex, subIndex)
	TextEditBoxSetText(editWindow.."Entry",speechText)
	WindowAssignFocus(editWindow.."Entry",true)
end

function MacroEditWindow.MacroEditOK()
	-- macros are never sub windows
	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex
	local numActions = UserActionMacroGetNumActions(hotbarId, itemIndex)
	
	if( numActions == 0 ) then
		-- If macro is empty, delete it
		MacroSystemDeleteMacroItem(itemIndex)
	else
		-- Grab the repeat settings
		local position = SliderBarGetCurrentPosition( ActionEditWindow.CurEditItem.windowName.."RepeatSliderBar" )
		local count = math.floor( ( position * 8 ) + 2 )
		UserActionMacroSetRepeatCount( hotbarId, itemIndex, count )
		if ButtonGetPressedFlag( ActionEditWindow.CurEditItem.windowName.."RepeatToggleButton" ) then
			UserActionMacroSetRepeatEnabled( hotbarId, itemIndex, true )
		else
			UserActionMacroSetRepeatEnabled( hotbarId, itemIndex, false )
		end	
		
		-- update the name
		macroName = ActionEditMacroNameEntry.Text
		UserActionMacroSetName(hotbarId, itemIndex, macroName)
	end
	
	-- update the macro list window
	MacroWindow.DisplayMacroList()
	HotbarSystem.UpdateMacroReferenceSlot(itemIndex)
	
	-- close any subwindow if it exists
	if( ActionEditWindow.CurEditMacroItem ~= nil ) then
		WindowSetShowing(ActionEditWindow.CurEditMacroItem.windowName,false)
		ActionEditWindow.CurEditMacroItem = nil
	end
	
	-- close this edit window
	WindowSetShowing(ActionEditWindow.CurEditItem.windowName,false)
	ActionEditWindow.CurEditItem = nil
	
	WindowSetShowing("ActionsWindow",false) -- Close the actions window
	
	if( DoesWindowNameExist("MacroIconPickerWindow") ) then
	    DestroyWindow("MacroIconPickerWindow")
	end
end

function MacroEditWindow.MacroActionLButtonDown()
	local slotName = SystemData.ActiveWindow.name
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	subIndex = WindowGetId(slotName)
	
	DragSlotSetExistingActionMouseClickData(hotbarId,itemIndex,subIndex)
end

function MacroEditWindow.MacroActionLButtonUp()
	local slotName = SystemData.ActiveWindow.name
	local parent = WindowUtils.GetActiveDialog()
	local hotbarId, itemIndex, subIndex = ActionEditWindow.GetActionInfo(parent)
	
	--Debug.Print("MacroEditWindow.MacroActionLButtonUp")
	if( SystemData.DragItem.DragType ~= SystemData.DragItem.TYPE_NONE ) then
		local hotbarId = ActionEditWindow.CurEditItem.hotbarId
		local itemIndex = ActionEditWindow.CurEditItem.itemIndex
		
		local actionIndex = WindowGetId(slotName)
	    local dropSuccess = DragSlotDropAction(hotbarId,itemIndex,actionIndex)
	    local actionId = UserActionGetId(hotbarId,itemIndex,actionIndex)
	    
	    if( dropSuccess ) then		
            local actionType = UserActionGetType(hotbarId, itemIndex, actionIndex)
            
            MacroEditWindow.UpdateMacroActionList("ActionEditMacro", hotbarId, itemIndex)

    		WindowSetShowing("ActionsWindow",true) -- Open the actions window
	    	--ActionEditWindow.OpenEditWindow(actionType,"ActionEditMacroActions",hotbarId,itemIndex,actionIndex)
	    	if actionType ~= SystemData.UserAction.TYPE_SKILL and actionType ~= SystemData.UserAction.TYPE_SPELL and actionType ~= SystemData.UserAction.TYPE_WEAPON_ABILITY and actionType ~= SystemData.UserAction.TYPE_USE_ITEM and actionType ~= SystemData.UserAction.TYPE_USE_OBJECTTYPE then
				if actionId >= 5000 then
					if (actionId == 5207) then
						Actions.ActionEditRequest = {ActionId = actionId, HotbarId = hotbarId, ItemIndex = itemIndex, SubIndex = actionIndex}
						Actions.TargetType()
					elseif (actionId >= 5500 and actionId < 5600) then
						Actions.ActionEditRequest = {ActionId = actionId, HotbarId = hotbarId, ItemIndex = itemIndex, SubIndex = actionIndex}
						Actions.TargetPetball()
					elseif (actionId >= 5600 and actionId < 5700) or (actionId >= 5800 and actionId < 5900) or actionId == 5156 or actionId == 5736 then
						Actions.ActionEditRequest = {ActionId = actionId, HotbarId = hotbarId, ItemIndex = itemIndex, SubIndex = actionIndex}
						Actions.TargetMount()
					else
						local speechText = ActionsWindow.ActionData[actionId].callback
						UserActionSpeechSetText(hotbarId, itemIndex, actionIndex, speechText)
					end
				else
					ActionEditWindow.OpenEditWindow(actionType,"ActionEditMacroActions",hotbarId,itemIndex,actionIndex,subIndex)
				end	
			else
				ActionEditWindow.OpenEditWindow(actionType,"ActionEditMacroActions",hotbarId,itemIndex,actionIndex,subIndex)
			end	

			
			local numActions = UserActionMacroGetNumActions(hotbarId, itemIndex)
			if( actionIndex == numActions ) then
				-- move the scrollbar up if there is one
				local scWidth, scHeight = WindowGetDimensions("ActionEditMacroActionsScrollChild")
				if( scWidth > MacroEditWindow.MACRO_SCROLLWINDOW_WIDTH ) then
					local scrollOffset = HorizontalScrollWindowGetOffset("ActionEditMacroActions")
					scrollOffset = scrollOffset + MacroEditWindow.MACRO_ACTION_WIDTH
					if( scrollOffset < scWidth ) then
						HorizontalScrollWindowSetOffset("ActionEditMacroActions", scrollOffset)
					end
				end
			end
		end
	end
end

function MacroEditWindow.MacroActionRButtonUp()
	local windowName = SystemData.ActiveWindow.name
	local actionIndex = WindowGetId(windowName)
	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex
	
	HotbarSystem.CreateUserActionContextMenuOptions(hotbarId, itemIndex, actionIndex, windowName)
	
	ContextMenu.ActivateLuaContextMenu(MacroEditWindow.ContextMenuCallback)
end

function MacroEditWindow.ContextMenuCallback(returnCode,param)
	if( param ~= nil ) then
		local bHandled = HotbarSystem.ContextMenuCallback(returnCode,param) 
		
		-- if it wasnt handled then check for macro action specific options
		if( bHandled == false ) then
			if( returnCode == HotbarSystem.ContextReturnCodes.CLEAR_ITEM ) then
				UserActionMacroRemoveAction(param.HotbarId, param.ItemIndex, param.SubIndex)
				MacroEditWindow.UpdateMacroActionList("ActionEditMacro", param.HotbarId, param.ItemIndex)
				
				local numActions = UserActionMacroGetNumActions(param.HotbarId, param.ItemIndex)
				if( param.SubIndex == numActions ) then
					-- move the scrollbar down if there is one, otherwise reset it to zero
					local scrollOffset = 0
					local scWidth, scHeight = WindowGetDimensions("ActionEditMacroActionsScrollChild")
					if( scWidth > MacroEditWindow.MACRO_SCROLLWINDOW_WIDTH ) then
						scrollOffset = HorizontalScrollWindowGetOffset("ActionEditMacroActions") - MacroEditWindow.MACRO_ACTION_WIDTH
						if( scrollOffset < 0 ) then
							scrollOffset = 0
						end
					end

					HorizontalScrollWindowSetOffset("ActionEditMacroActions", scrollOffset)
				end
			end
		end
	end	
end

function MacroEditWindow.MacroActionMouseOver()
	local this = SystemData.ActiveWindow.name
	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex	
	local actionIndex = WindowGetId(this)

	local actionType = SystemData.UserAction.TYPE_NONE
	-- default id to the slot so it shows the item properties when there is only a binding
	local itemId = actionIndex
	
	actionType = UserActionGetType(hotbarId,itemIndex,actionIndex)
	local actionId = UserActionGetId(hotbarId,itemIndex,actionIndex)
	if( actionId ~= 0 ) then
		itemId = actionId
	end
	
	if( actionType == SystemData.UserAction.TYPE_SKILL ) then
		-- NOTE: Need to fix this. Id 0 is also a null check, so no tooltip for Alchemy
		itemId = itemId + 1
	end	
	
	if (actionId and ((actionId > 5000 and actionId < 15000) or (actionId == 53 or actionId == 54 or actionId == 50))) then
		local actionData = ActionsWindow.ActionData[actionId]

		local name = L""
		if (actionData.nameTid) then
			name = GetStringFromTid(actionData.nameTid)
		else
			name = actionData.nameString
		end
		local desc = L""
		if (not actionData.detailTid) then
			desc = actionData.detailString
		else
			desc = GetStringFromTid(actionData.detailTid)
		end
		local itemData
		if (actionId == 5015) then
			local backpackId = WindowData.PlayerEquipmentSlot[EquipmentData.EQPOS_BACKPACK].objectId
	
			if backpackId ~= 0 then
				itemData = {
					windowName = "ActionEditMacro",
					itemLoc = {hotbarId=hotbarId, itemIndex=itemIndex, subIndex=actionIndex},
					itemId = backpackId,
					itemType = WindowData.ItemProperties.TYPE_ITEM,
				}
				ItemProperties.SetActiveItem(itemData)
			end
		else
			itemData =
			{
				windowName = "ActionEditMacro",
				itemId = actionId,
				detail = ItemProperties.DETAIL_LONG,
				itemLoc = {hotbarId=hotbarId, itemIndex=itemIndex, subIndex=actionIndex},
				itemType = WindowData.ItemProperties.TYPE_WSTRINGDATA,
				title =	name,
				body = desc
				
			}	
		end
		ItemProperties.SetActiveItem(itemData)
	else
		itemData = { windowName = "ActionEditMacro",
						itemId = itemId,
						itemType = WindowData.ItemProperties.TYPE_ACTION,
						detail = ItemProperties.DETAIL_LONG,
						actionType = actionType,
						itemLoc = {hotbarId=hotbarId, itemIndex=itemIndex, subIndex=actionIndex}
					 }
		ItemProperties.SetActiveItem(itemData)
	end
	
	if( SystemData.DragItem.DragType ~= SystemData.DragItem.TYPE_NONE ) then
		local actionDividerImage = this.."Divider"
		WindowSetAlpha(actionDividerImage, 1.0)
	end
end

function MacroEditWindow.MacroActionMouseOverEnd()
	local windowName = SystemData.ActiveWindow.name
	local actionDividerImage = windowName.."Divider"
	
	WindowSetAlpha(actionDividerImage, 0.0)
	
	ItemProperties.ClearMouseOverItem()
end

function MacroEditWindow.MacroEditIcon()
	local parentName = SystemData.ActiveWindow.name
	if( DoesWindowNameExist("MacroIconPickerWindow") == false ) then
		CreateWindowFromTemplate( "MacroIconPickerWindow", "MacroPickerWindowTemplate", "Root")
		MacroPickerWindow.DrawMacroTable("MacroIconPickerWindow")
	end
	
	WindowClearAnchors("MacroIconPickerWindow")
	WindowAddAnchor( "MacroIconPickerWindow", "topleft", parentName, "bottomleft", 0, 0)
	WindowSetShowing("MacroIconPickerWindow", true)
	
	MacroPickerWindow.SetAfterMacroSelectionFunction(function() MacroEditWindow.MacroEditIconCallback(MacroPickerWindow.MacroSelected)  end)
end

function MacroEditWindow.MacroEditIconCallback(newIconId)
	local hotbarId = ActionEditWindow.CurEditItem.hotbarId
	local itemIndex = ActionEditWindow.CurEditItem.itemIndex

	UserActionSetIconId(hotbarId, itemIndex, 0, newIconId)
	local texture, x, y = GetIconData(newIconId)
	DynamicImageSetTexture( "ActionEditMacroNameIcon", texture, x, y )
	
	DestroyWindow("MacroIconPickerWindow")
end

function MacroEditWindow.EmptyButtonMouseOver()
	local buttonName = SystemData.ActiveWindow.name
	local text = GetStringFromTid(MacroEditWindow.TID_MACRO_DRAG_TOOLTIP)
	Tooltips.CreateTextOnlyTooltip(buttonName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function MacroEditWindow.MacroIconMouseOver()
	local buttonName = SystemData.ActiveWindow.name
	local text = GetStringFromTid(MacroEditWindow.TID_MACRO_ICON_TOOLTIP)
	Tooltips.CreateTextOnlyTooltip(buttonName, text)
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function MacroEditWindow.UpdateSliderBar()
	local position = SliderBarGetCurrentPosition( ActionEditWindow.CurEditItem.windowName.."RepeatSliderBar" )
	local count = math.floor( ( position * 8 ) + 2 )
	LabelSetText( ActionEditWindow.CurEditItem.windowName.."RepeatVal", StringToWString(tostring(count)) )
end
