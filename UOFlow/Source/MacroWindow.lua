---------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

MacroWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
MacroWindow.MacroSelected = nil
MacroWindow.NumItemsCreated = 0
MacroWindow.RecordingIndex = 0
MacroWindow.RecordingKey = false

MacroWindow.TID_MACRO = 3000394
MacroWindow.TID_MACROS = 3000172 
MacroWindow.TID_NOMACRO = 1078292
MacroWindow.TID_MACROCOLON = 1094841 -- "Macro:"
MacroWindow.TID_CREATE = 1077830
MacroWindow.TID_DESTROY_MACRO = 1078351
MacroWindow.TID_NO_KEYBINDING = 1078509
MacroWindow.TID_BINDING_CONFLICT_TITLE = 1079169
MacroWindow.TID_BINDING_CONFLICT_BODY = 1079170
MacroWindow.TID_BINDING_CONFLICT_QUESTION = 1094839
MacroWindow.TID_YES = 1049717
MacroWindow.TID_NO = 1049718
----------------------------------------------------------------
-- MainMenuWindow Functions
----------------------------------------------------------------

-- The macrolist is treated internally as a hotbar that you cant actually use

-- OnInitialize Handler
function MacroWindow.Initialize()
	Interface.OnCloseCallBack["MacroWindow"] = MacroWindow.OnClose

	ButtonSetText("AddMacroButton", GetStringFromTid(MacroWindow.TID_CREATE))
    
    LabelSetText("MacroScrollWindowNoMacros",GetStringFromTid(MacroWindow.TID_NOMACRO))
    
	WindowRegisterEventHandler( "MacroWindow", SystemData.Events.INTERFACE_KEY_RECORDED, "MacroWindow.KeyRecorded" )
	WindowRegisterEventHandler( "MacroWindow", SystemData.Events.INTERFACE_KEY_CANCEL_RECORD, "MacroWindow.KeyCancelRecord" )
	WindowUtils.SetWindowTitle("MacroWindow", GetStringFromTid(MacroWindow.TID_MACROS))
	WindowUtils.RestoreWindowPosition("MacroWindow")
end

function MacroWindow.Shutdown()
	WindowUtils.SaveWindowPosition("MacroWindow")
end

function MacroWindow.OnShown()
	MacroWindow.DisplayMacroList()
end

function MacroWindow.AddMacro()
	local macroIndex = MacroSystemAddMacroItem()
	UserActionMacroSetName(SystemData.MacroSystem.STATIC_MACRO_ID,macroIndex,GetStringFromTid(MacroWindow.TID_MACRO)..macroIndex)
	UserActionSetIconId(SystemData.MacroSystem.STATIC_MACRO_ID,macroIndex,0)
	ActionEditWindow.OpenEditWindow(SystemData.UserAction.TYPE_MACRO,nil,SystemData.MacroSystem.STATIC_MACRO_ID,macroIndex)

    -- do a custom anchor here so it doesnt overlap the actions window
    -- TODO: Removing anchors for now, some weird behavior when moving one window that has windows anchored to it
    --WindowClearAnchors("ActionEditMacro")
    --WindowAddAnchor("ActionEditMacro","topright","MacroWindow","topleft",10,0)
    --WindowClearAnchors("ActionsWindow")
    --WindowAddAnchor("ActionsWindow","topright","ActionEditMacro","topleft",10,0)
    
    WindowSetShowing("ActionsWindow", true) -- Open the actions window
end

function MacroWindow.DisplayMacroList()
	local baseMacroItemName = "MacroScrollWindowScrollChildItem"
   	local numMacros = MacroSystemGetNumMacros()
   	
   	if( numMacros == 0 ) then
   		WindowSetShowing("MacroScrollWindowNoMacros",true)
   	else
		WindowSetShowing("MacroScrollWindowNoMacros",false)
	end
	
    for i=1,numMacros do
    	local currentMacroWindowName = baseMacroItemName..i
    	
    	if( i > MacroWindow.NumItemsCreated ) then
    		CreateWindowFromTemplate( currentMacroWindowName, "MacroItemTemplate", "MacroScrollWindowScrollChild" )
    		WindowSetId(currentMacroWindowName, i)
    		WindowSetId(currentMacroWindowName.."SquareIcon", i)
			
			MacroWindow.NumItemsCreated = MacroWindow.NumItemsCreated + 1
		end

		-- reanchor window
		WindowClearAnchors(currentMacroWindowName)
		if (i==1) then
         	WindowAddAnchor( currentMacroWindowName, "topleft", "MacroScrollWindowScrollChild", "topleft", 10, 0)
		else
        	WindowAddAnchor( currentMacroWindowName, "bottomleft", baseMacroItemName..(i-1), "topleft", 0, 0)
		end
        
        local iconId = UserActionGetIconId(SystemData.MacroSystem.STATIC_MACRO_ID,i,0)
        local iconTexture, x, y = GetIconData(iconId)
        DynamicImageSetTexture(currentMacroWindowName.."SquareIcon", iconTexture, x, y)
        DynamicImageSetTexture( currentMacroWindowName.."SquareIconBG", MiniTexturePack.DB[MiniTexturePack.Current].texture .. "Icon", x, y )
        
        if( UserActionIsTargetModeCompat(SystemData.MacroSystem.STATIC_MACRO_ID, i, 0) ) then
			WindowSetShowing(currentMacroWindowName.."Disabled", false)
			LabelSetTextColor( currentMacroWindowName.."Name", 255, 255, 255 )
		else
			WindowSetShowing(currentMacroWindowName.."Disabled", true)
			LabelSetTextColor( currentMacroWindowName.."Name", 128, 128, 128 )
		end
		
		local macroName = UserActionMacroGetName(SystemData.MacroSystem.STATIC_MACRO_ID,i)
		LabelSetText(currentMacroWindowName.."Name",macroName)

		local bindingStr = UserActionMacroGetBinding(SystemData.MacroSystem.STATIC_MACRO_ID,i)
		if( bindingStr ~= L"" ) then
			LabelSetText(currentMacroWindowName.."Binding",bindingStr)
		else
			LabelSetText(currentMacroWindowName.."Binding",GetStringFromTid(MacroWindow.TID_NO_KEYBINDING) )
		end		
        
        WindowSetShowing(currentMacroWindowName, true)

		WindowSetId(currentMacroWindowName, i) 
    end
    
    -- hide the existing unused windows
    for i=(numMacros+1), MacroWindow.NumItemsCreated do
		local currentMacroWindowName = baseMacroItemName..i
		WindowSetShowing(currentMacroWindowName, false)
		WindowClearAnchors(currentMacroWindowName)
    end
    
    if(numMacros < 5) then
		ScrollWindowSetOffset( "MacroScrollWindow", 0 )
	end
    ScrollWindowUpdateScrollRect("MacroScrollWindow")
end                                           

function MacroWindow.PickupMacro(flags)
	local macroIndex = WindowGetId(SystemData.ActiveWindow.name)
	local macroId = UserActionGetId(SystemData.MacroSystem.STATIC_MACRO_ID,macroIndex,0)
	local iconId = UserActionGetIconId(SystemData.MacroSystem.STATIC_MACRO_ID,macroIndex,0)
	
	
	if flags == SystemData.ButtonFlags.CONTROL then
		local blockBar = HotbarSystem.GetNextHotbarId()
		Interface.SaveBoolean("Hotbar" .. blockBar .. "_IsBlockbar", true)
		HotbarSystem.SpawnNewHotbar()
		
		HotbarSystem.SetActionOnHotbar(SystemData.UserAction.TYPE_MACRO_REFERENCE, macroId, iconId, blockBar,  1)
		
		local scaleFactor = 1/InterfaceCore.scale	
		
		local propWindowWidth = Hotbar.BUTTON_SIZE
		local propWindowHeight = Hotbar.BUTTON_SIZE
		
		-- Set the position
		local mouseX = SystemData.MousePosition.x - 30
		if mouseX + (propWindowWidth / scaleFactor) > SystemData.screenResolution.x then
			propWindowX = mouseX - (propWindowWidth / scaleFactor)
		else
			propWindowX = mouseX
		end
			
		local mouseY = SystemData.MousePosition.y - 15
		if mouseY + (propWindowHeight / scaleFactor) > SystemData.screenResolution.y then
			propWindowY = mouseY - (propWindowHeight / scaleFactor)
		else
			propWindowY = mouseY
		end
		
		WindowSetOffsetFromParent("Hotbar" .. blockBar, propWindowX * scaleFactor, propWindowY * scaleFactor)
		WindowSetMoving("Hotbar" .. blockBar, true)
		
    else
		DragSlotSetActionMouseClickData(SystemData.UserAction.TYPE_MACRO_REFERENCE,macroId,iconId)
	end
end

function MacroWindow.OnItemRButtonUp()
	local slotWindow = SystemData.ActiveWindow.name
	local macroIndex = WindowGetId(slotWindow)
	
	HotbarSystem.CreateUserActionContextMenuOptions(SystemData.MacroSystem.STATIC_MACRO_ID, macroIndex, 0, slotWindow)
	
	ContextMenu.CreateLuaContextMenuItem(HotbarSystem.TID_ASSIGN_HOTKEY,0,HotbarSystem.ContextReturnCodes.ASSIGN_KEY,macroIndex)
	
	ContextMenu.ActivateLuaContextMenu(MacroWindow.ContextMenuCallback)
end

function MacroWindow.ContextMenuCallback(returnCode,param)
	if( param ~= nil ) then
		local bHandled = HotbarSystem.ContextMenuCallback(returnCode,param) 
		
		-- if it wasnt handled then check for macro specific options
		if( bHandled == false ) then
			if( returnCode == HotbarSystem.ContextReturnCodes.CLEAR_ITEM ) then
                local okayButton = { textTid=UO_StandardDialog.TID_OKAY, callback=function() MacroSystemDeleteMacroItem(param.ItemIndex) MacroWindow.DisplayMacroList() end }
                local cancelButton = { textTid=UO_StandardDialog.TID_CANCEL }				
				local DestroyConfirmWindow = 
				{
				    windowName = "MacroWindow",
					titleTid = HotbarSystem.TID_CLEAR_ITEM,
					bodyTid = MacroWindow.TID_DESTROY_MACRO,
                    buttons = { okayButton, cancelButton }
				}
					
				UO_StandardDialog.CreateDialog(DestroyConfirmWindow)			
			elseif( returnCode == HotbarSystem.ContextReturnCodes.ASSIGN_KEY ) then
				WindowClearAnchors("AssignHotkeyInfo")
				WindowAddAnchor("AssignHotkeyInfo","topleft","MacroScrollWindowScrollChildItem"..param,"bottomleft",0,-6)
				WindowSetShowing("AssignHotkeyInfo",true)
			
				MacroWindow.RecordingIndex = param
				MacroWindow.RecordingKey = true
				BroadcastEvent( SystemData.Events.INTERFACE_RECORD_KEY )				
			end
		end
	end
end

function MacroWindow.KeyRecorded()
	if( MacroWindow.RecordingKey == true ) then
	    MacroWindow.RecordingKey = false
		--Debug.Print("MacroWindow.RecordingIndex: "..MacroWindow.RecordingIndex)
		WindowSetShowing("AssignHotkeyInfo",false)

		if( SystemData.BindingConflictType ~= SystemData.BindType.BINDTYPE_NONE )then
			body = GetStringFromTid( MacroWindow.TID_BINDING_CONFLICT_BODY )..L"\n\n"..HotbarSystem.GetKeyName(SystemData.BindingConflictHotbarId, SystemData.BindingConflictItemIndex, SystemData.BindingConflictType)..L"\n\n"..GetStringFromTid( MacroWindow.TID_BINDING_CONFLICT_QUESTION )
			
			local yesButton = { textTid = MacroWindow.TID_YES,
								callback =	function()
											HotbarSystem.ReplaceKey(
												SystemData.BindingConflictHotbarId, SystemData.BindingConflictItemIndex, SystemData.BindingConflictType,
												SystemData.MacroSystem.STATIC_MACRO_ID, MacroWindow.RecordingIndex, SystemData.BindType.BINDTYPE_MACRO,
												SystemData.RecordedKey, L"")
											end
							  }
			local noButton = { textTid = MacroWindow.TID_NO }
			local windowData = 
			{
				windowName = "MacroWindow", 
				titleTid = MacroWindow.TID_BINDING_CONFLICT_TITLE, 
				body = body, 
				buttons = { yesButton, noButton }
			}
			UO_StandardDialog.CreateDialog( windowData )
	    else
            UserActionMacroUpdateBinding(SystemData.MacroSystem.STATIC_MACRO_ID,MacroWindow.RecordingIndex,SystemData.RecordedKey)

		    local MacroLabel = "MacroScrollWindowScrollChildItem"..MacroWindow.RecordingIndex.."Binding"
		    if( SystemData.RecordedKey ~= L"" ) then
			    LabelSetText(MacroLabel, SystemData.RecordedKey)
		    else
			    LabelSetText(MacroLabel, GetStringFromTid(MacroWindow.TID_NO_KEYBINDING))
		    end
		end
	end
end

function MacroWindow.KeyCancelRecord()
	if( MacroWindow.RecordingKey == true ) then
	    MacroWindow.RecordingKey = false
		WindowSetShowing("AssignHotkeyInfo",false)
	end
end