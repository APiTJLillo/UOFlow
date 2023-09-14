----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ChatWindow = {}

----------------------------------------------------------------
-- Saved Variables
----------------------------------------------------------------
ChatWindow.Settings = {}

ChatWindow.history = nil
ChatWindow.SelectedTabNumber = 1
ChatWindow.BaseVersion = 1.5
ChatWindow.CurrentVersion = 1.5

local lastChatWindowName = "ChatWindow"
local skipSave = false
local fDirtyDelay = 0.0	-- artificial delay used when LoadSettings gets called
local bDirty = false
local bLoading = false
local bUnDocking = false
local UnDockingWindowName = nil
----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
local WINDOW_MIN_ALPHA = 0.0
local WINDOW_FULL_ALPHA = 1.0
local DEFAULT_WINDOW_MAX_ALPHA = 0.7
local FADE_TIME = 0.6

-- Delay to fade the chat window.  Used for Fade in/out.
ChatWindow.FADE_OUT_DELAY = 2.0
ChatWindow.FADE_IN_DELAY = 0.5
ChatWindow.SAVE_DELAY = 15.0
ChatWindow.ALPHA_FADE_TIMER = 2
-- Table to hold all of the states of each DockableWindow, this will allow us to 
-- fade each grouping of DockableWindows.
ChatWindow.dockableWindowData = {}
-- If this is true the only visible elements will be the log display, scrollbar, and channel button
ChatWindow.windowLocked = false
ChatWindow.autohide = true
ChatWindow.topWindow = ""
ChatWindow.firstGChatSelect = true

-- FIXME:  Maybe these should go in a table????
local curChannel            = nil   -- The current channel you are in, nil if you haven't said anything yet, or you're inputting a command
local prevChannel           = nil   -- The last channel you were chatting in...how we know which channel to switch to by default for new chats   
local whisperTarget         = nil   -- The target of your tell
local replyIndex            = 1     -- Initial reply-to should go to the FIRST person who whispered you...

local c_TELL_TARGET_COMMAND = L"/tell"
local c_REPLY_COMMAND       = L"/reply"

ChatWindow.TID = { Chat=3000131, Journal=3000129, System=1078905, TextColors=1111678,RenameTabDesc=1111679,Rename=1111680,Cancel=1006045,
                   Opacity=1111681,TabOptions=1111682,Background=1111683,AutoHide=1111684,ShowTimestamp=1111685,
                   Font=1111686,NewTab=1111687,RenameTab=1111688,RemoveTab=1111689,SetOpacity=1111690,ChatFilters=1111674,
                   UnlockWindow=1111696,LockWindow=1111697, ChatButtonTooltip=1111847, ChatButtonOk=1006044,
                   FadeOutOpacity=1112104, FadeInOpacity=1112105 }

local function IsSlashCommandInChannel( slashCommand, channel )
    return ( slashCommand ~= nil and
             channel ~= nil and
             channel.slashCmds ~= nil and
             channel.slashCmds[slashCommand] == 1 )
end

----------------------------------------------------------------
-- Saved Settings Variables
----------------------------------------------------------------

ChatWindow.Windows = {}
ChatWindow.Windows[1] = {}
ChatWindow.Windows[1].Tabs = {}
ChatWindow.Windows[1].activeTab = 1
ChatWindow.Windows[1].wndName = "ChatWindow"
ChatWindow.Windows[1].resizeButton = "ChatWindowResizeButton"
ChatWindow.Windows[1].background = "ChatWindowBackground"
ChatWindow.Windows[1].showTimestamp = false
ChatWindow.Windows[1].windowMinAlpha = WINDOW_MIN_ALPHA
ChatWindow.Windows[1].windowMaxAlpha = DEFAULT_WINDOW_MAX_ALPHA

local function GetMouseOverChatWindow()
    -- run up the window's parent chain until we find a chat window, or not
    local wndName = SystemData.MouseOverWindow.name
    while wndName ~= nil
        and wndName ~= ""
        and wndName ~= "NONE"         
        and DoesWindowExist( wndName) do
        local id = WindowGetId(wndName)
        if id ~= nil
            and id > 0
            and ChatWindow.Windows[id] ~= nil
            and ChatWindow.Windows[id].wndName == wndName then
                return ChatWindow.Windows[id]
        end
        wndName = WindowGetParent(wndName)
    end
end

local function GetMouseOverChatWindowIndex()
    -- run up the window's parent chain until we find a chat window, or not
    local wndName = SystemData.MouseOverWindow.name
    while wndName ~= nil
        and wndName ~= ""
        and wndName ~= "NONE" do
        local id = WindowGetId(wndName)
        if id ~= nil
            and id > 0
            and ChatWindow.Windows[id] ~= nil
            and ChatWindow.Windows[id].wndName == wndName then
                return WindowGetId(ChatWindow.Windows[id].wndName)
        end
        wndName = WindowGetParent(wndName)
    end
    -- return 0 for a fail case
    return 0
end

local function IsChannelMenuOpen()
    return WindowGetShowing( "ChatChannelSelectionWindow" )
end

local function CanRemoveTab( wndNum, tabNum )
    if ( wndNum == 1
        and tabNum == 1 ) then
        return false
    end
    return true
end

local function IsTextInputWindowActive()
	return WindowHasFocus( "ChatWindowContainerTextInput" )
end

----------------------------------------------------------------
-- ChatWindow Functions
----------------------------------------------------------------

-- OnInitialize Handler
function ChatWindow.Initialize()
    ChatSettings.SetupChannelColorDefaults( false )

    -- Hide the Text Input Window
    CreateWindow( "ChatWindowContainer", false )
    WindowSetParent( "ChatWindowContainer", "Root" )
    WindowSetShowing( "ChatWindowContainer", false )
    WindowSetAlpha( "ChatWindowContainerTextInput", DEFAULT_WINDOW_MAX_ALPHA )
    WindowSetAlpha( "ChatWindowResizeButton", WINDOW_MIN_ALPHA )
    WindowSetAlpha( "ChatWindowBackground", WINDOW_MIN_ALPHA )
    WindowSetAlpha ("ChatWindowContainerBG", DEFAULT_WINDOW_MAX_ALPHA)
    WindowSetId("ChatWindowChatTab", 1)
    --WindowSetAlpha ("ChatWindowOptionsButton", 100)

    -- DAB TODO: Removed language toggle thing
	--ChatWindow.OnLanguageToggled()

    WindowSetShowing("ChatWindowResizeButton", WindowGetMovable( "ChatWindow" ))

    CreateWindowFromTemplate ("ChatWindowInputTextButton",      "ChatWindowInputTextButton",        "Root");
    WindowClearAnchors("ChatWindowInputTextButton")
    WindowAddAnchor("ChatWindowInputTextButton","bottomleft","ChatWindow","topleft",0,0)
    WindowSetDimensions("ChatWindowInputTextButton",24,27)

    CreateWindow( "ChatWindowRenameWindow", false )
    LabelSetText("ChatWindowRenameWindowLabel", GetStringFromTid(ChatWindow.TID.RenameTabDesc))
    ButtonSetText("ChatWindowRenameWindowRenameButton", GetStringFromTid(ChatWindow.TID.Rename) )
    ButtonSetText("ChatWindowRenameWindowCancelButton", GetStringFromTid(ChatWindow.TID.Cancel) )

    CreateWindowFromTemplate("ChatWindowSetOpacityWindow", "ChatWindowSetOpacityWindow", "Root")
    LabelSetText("ChatWindowSetOpacityWindowLabelMinAlpha", GetStringFromTid(ChatWindow.TID.FadeOutOpacity) )
    LabelSetText("ChatWindowSetOpacityWindowLabelMaxAlpha", GetStringFromTid(ChatWindow.TID.FadeInOpacity) )
    ButtonSetText("ChatWindowSetOpacityWindowOKButton", GetStringFromTid(ChatWindow.TID.ChatButtonOk) )
    WindowSetShowing("ChatWindowSetOpacityWindow", false)
    WindowUtils.SetWindowTitle("ChatWindowSetOpacityWindow", GetStringFromTid(ChatWindow.TID.Opacity) )
    Interface.OnCloseCallBack["ChatWindowSetOpacityWindow"] = ChatWindow.CloseSetOpacityWindow

    CreateWindowFromTemplate ("ChatWindowContextAutoHide", "ChatContextMenuItemCheckBox", "Root")
    LabelSetText( "ChatWindowContextAutoHideLabel", GetStringFromTid(ChatWindow.TID.AutoHide) )
    WindowRegisterCoreEventHandler("ChatWindowContextAutoHide", "OnLButtonUp", "ChatWindow.ToggleAutoHide")
    WindowSetShowing("ChatWindowContextAutoHide", false)

    CreateWindowFromTemplate ("ChatWindowContextShowTimestamp", "ChatContextMenuItemCheckBox", "Root")
    LabelSetText( "ChatWindowContextShowTimestampLabel", GetStringFromTid(ChatWindow.TID.ShowTimestamp) )
    WindowRegisterCoreEventHandler("ChatWindowContextShowTimestamp", "OnLButtonUp", "ChatWindow.ToggleTimestamp")
    WindowSetShowing("ChatWindowContextShowTimestamp", false)
    
    CreateWindowFromTemplate ("ChatWindowTabMenuDivider", "ChatContextMenuItemDivider", "Root")
    WindowSetShowing("ChatWindowTabMenuDivider", false)    
    
    -- Initializes the submenu that allows users to choose the channel of their chat entry.
    ChatWindow.InitializeChannelMenuSelectionWindow()    
    
    ChatWindow.LoadSettings()

    -- Register for the 'BEGIN_ENTER_CHAT' event
    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.CHAT_ENTER_START,       "ChatWindow.OnEnterChatText")
    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.TEXT_ARRIVED,      "ChatWindow.UpdateNewTextAlert")       
    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.USER_SETTINGS_UPDATED, "ChatWindow.ResetScrollLimits" )
    
    --WindowRegisterEventHandler( "ChatWindow", SystemData.Events.CHAT_REPLY,				"ChatWindow.OnReply")
    --WindowRegisterEventHandler( "ChatWindow", SystemData.Events.SETTINGS_CHAT_UPDATED,  "ChatWindow.UpdateChatSettings")    
    
    --WindowRegisterEventHandler( "ChatWindow", SystemData.Events.RESOLUTION_CHANGED,     "ChatWindow.UpdateChatSettings")  
    -- DAB TODO: Removed social window button
    --WindowRegisterEventHandler( "ChatWindow", SystemData.Events.PLAYER_INFO_CHANGED,    "ChatWindow.UpdateSocialWindowButton")
        
    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.L_BUTTON_DOWN_PROCESSED, "ChatWindow.OnLButtonDownProcessed")
    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.R_BUTTON_DOWN_PROCESSED, "ChatWindow.OnRButtonDownProcessed")

    WindowRegisterEventHandler( "ChatWindow", SystemData.Events.GHAT_ROSTER_UPDATE,       "ChatWindow.OnGChatRosterUpdate")
    
    
    
    for idxW, wnd in pairs(ChatWindow.Windows) do
        --WindowSetAlpha( wnd.optionsButton, wnd.windowMaxAlpha )
        WindowSetAlpha( wnd.resizeButton, wnd.windowMaxAlpha )
        WindowSetAlpha( wnd.background, wnd.windowMaxAlpha )
        for idxT, tab in pairs(wnd.Tabs) do
            WindowSetAlpha( tab.tabButton, wnd.windowMinAlpha )
            ChatWindow.ScrollToBottom( idxW )
        end
    end

    -- Set the history (this preserves it logging in/out)
    if( GameData.ChatData.history ) then
        TextEditBoxSetHistory("ChatWindowContainerTextInput", GameData.ChatData.history )   
    end

    -- Clear the channel history, if there is one. 
    -- This fixes bug: Chat Text Defaults --> sticks to last channel in between character switches
    curChannel = nil
    prevChannel = nil

    ChatWindow.UpdateChatSettings()
    ChatWindow.ResetTextBox ()
    ChatWindow.InitRootChatTab()
    ChatWindow.ResetRootDockableWindowDataVariables()
    for idxW, wnd in pairs(ChatWindow.Windows) do
        -- If you are a root tab
        if (ChatWindow.dockableWindowData[idxW].idxRootWindow == idxW)
        then
            ChatWindow.PerformFadeOut(idxW)
        end
        -- Set all tabs to their set Timestamp preference
        LogDisplaySetShowTimestamp( wnd.Tabs[1].tabWindow, wnd.showTimestamp)
    end
    
    ChatWindow.LockWindow(ChatWindow.windowLocked)
end

function ChatWindow.OnSetTopDockWindow(newTopWindowName)
	local isTopTabNameTop
    local newTopWindowIndex = WindowGetId( newTopWindowName )
    local rootWindowIndex = WindowGetId( DockableWindowGetRootName(newTopWindowName) )
    for idxW, wnd in pairs(ChatWindow.Windows) do    
        -- If this is the current window in focus, or these windows share the same Root window; Fade them in.
        if (rootWindowIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
        then        
            WindowSetAlpha ( wnd.wndName.."Tab", wnd.windowMaxAlpha )

            isTopTabNameTop = (newTopWindowName == wnd.wndName)
            if (isTopTabNameTop == true)
            then
                --WindowSetAlpha ( wnd.resizeButton, WINDOW_FULL_ALPHA )
                WindowSetShowing( wnd.background, true )
                WindowSetAlpha( wnd.background, wnd.windowMaxAlpha )
                local logDisplay = wnd.Tabs[1].tabWindow
                LogDisplayResetLineFadeTime( logDisplay )
                
                -- Only show the scroll bar if this window has an active scroll region
                if (LogDisplayIsScrollbarActive( wnd.Tabs[1].tabWindow ) == true)
                then
                    TextLogDisplayShowScrollbar( wnd.Tabs[1].tabWindow, true)
                end
            else
                if (wnd.background ~= nil and wnd.Tabs[1].tabWindow ~= nil) -- and wnd.resizeButton ~= nil
                then
                    --WindowSetAlpha ( wnd.resizeButton, WINDOW_MIN_ALPHA )
                    WindowSetShowing( wnd.background, false )
                    TextLogDisplayShowScrollbar( wnd.Tabs[1].tabWindow, false)
                end
            end
            -- Reset the timers so we do not fade in/out
            -- This check will determine if a window has just been undocked, and will not
            -- zero out the timer
            if (ChatWindow.dockableWindowData[idxW].isUndocking == false)
            then
                ChatWindow.dockableWindowData[idxW].fadeInTimer = 0
                ChatWindow.dockableWindowData[idxW].fadeOutTimer = 0
                ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = true
            else
                -- Set it to false, because we've handled this case
                ChatWindow.dockableWindowData[idxW].isUndocking = false
            end
        end
    end
end
function ChatWindow.OnMouseOver()
    local overWndIndex = GetMouseOverChatWindowIndex()
    if (overWndIndex == 0)
    then
        overWndIndex = 1
    end
    LogDisplayResetLineFadeTime( ChatWindow.Windows[overWndIndex].Tabs[1].tabWindow )
    local rootName = DockableWindowGetRootName(ChatWindow.Windows[overWndIndex].wndName)
    local rootIndex = WindowGetId(rootName)
    -- Early out if this window is already at the maximum Alpha
    if (ChatWindow.dockableWindowData[overWndIndex].isWindowAlphaMin == false)
    then
        -- Reset the timer, because the user has moused over
        for idxW, wnd in pairs(ChatWindow.Windows) do
            if (rootIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
            then
                ChatWindow.dockableWindowData[idxW].fadeOutTimer = 0
            end
        end
        
        return
    end
    
    -- Loop over all windows to determine if this window is docked to the same "root" as the moused over window
    -- Then set all variables accordingly
    if( ChatWindow.windowLocked == false ) then
		for idxW, wnd in pairs(ChatWindow.Windows) do

			if (rootIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
			then
				ChatWindow.dockableWindowData[idxW].fadeInTimer = ChatWindow.FADE_IN_DELAY
				ChatWindow.dockableWindowData[idxW].fadeOutTimer = 0
				ChatWindow.dockableWindowData[idxW].idxRootWindow  = rootIndex
			end
		end
	end
end

function ChatWindow.OnMouseOverEnd()
    local overWndIndex = GetMouseOverChatWindowIndex()
    if (overWndIndex == 0)
    then
        overWndIndex = 1
    end
    local rootName = DockableWindowGetRootName(ChatWindow.Windows[overWndIndex].wndName)
    local rootIndex = WindowGetId(rootName)
    -- Early out if this window is already at the maximum Alpha
    if (ChatWindow.dockableWindowData[overWndIndex].isWindowAlphaMin == true)
    then
        -- Refresh timer state
        for idxW, wnd in pairs(ChatWindow.Windows) do
            if (rootIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
            then
                ChatWindow.dockableWindowData[idxW].fadeInTimer = 0
            end
        end
        return
    end
    -- Loop over all windows to determine if this window is docked to the same "root" as the moused over window
    -- Then set all variables accordingly
    for idxW, wnd in pairs(ChatWindow.Windows) do
        if (rootIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
        then
            ChatWindow.dockableWindowData[idxW].fadeOutTimer = ChatWindow.FADE_OUT_DELAY
            ChatWindow.dockableWindowData[idxW].fadeInTimer = 0
            ChatWindow.dockableWindowData[idxW].idxRootWindow  = WindowGetId(rootName)
        end
    end
end

-- Perform Fade functions
-- rootWindowIndex used to determine the grouping of windows to fade
function ChatWindow.PerformFadeIn( rootWindowIndex )
    --Debug.Print("ChatWindow.PerformFadeIn: "..tostring(rootWindowIndex))
    local topTabName = DockableWindowGetTopWindowName(ChatWindow.Windows[rootWindowIndex].wndName)
    for idxW, wnd in pairs(ChatWindow.Windows) do
        -- If this is the current window in focus, or these windows share the same Root window; Fade them in.
        if ( wnd.wndName~=nil and rootWindowIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow )
        then
			for idxT, tab in pairs(wnd.Tabs) do
				--Debug.Print("Tab Alpha is: "..WindowGetAlpha(wnd.wndName.."Tab"))
				WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, WindowGetAlpha(wnd.wndName.."Tab"), wnd.windowMaxAlpha, 0.5, false, 0, 0 )
			end
			WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, WindowGetAlpha(wnd.background), wnd.windowMaxAlpha, 0.5, false, 0, 0 )
			WindowSetShowing( wnd.background, true )
			if (topTabName ~= wnd.wndName)
            then
                WindowSetShowing(wnd.background, false)
            end
            
            if( ChatWindow.windowLocked == true ) then
				WindowSetAlpha ( wnd.resizeButton, WINDOW_MIN_ALPHA )
			else
				WindowSetAlpha ( wnd.resizeButton, wnd.windowMaxAlpha )
			end
			
            local logDisplay = wnd.Tabs[1].tabWindow
            LogDisplayResetLineFadeTime( logDisplay )
            ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = false
        end
    end
end

-- rootWindowIndex used to determine the grouping of windows to fade
function ChatWindow.PerformFadeOut( rootWindowIndex )
	if ( (IsChannelMenuOpen() or IsTextInputWindowActive() == true) and rootWindowIndex == 1 )
    then
        -- If the Chat dockable window has the text input or channel window open, don't fade just yet
        return
    end

    for idxW, wnd in pairs(ChatWindow.Windows) do
        if (rootWindowIndex ~= nil and ChatWindow.dockableWindowData[idxW].isContextMenuShowing == true
            and ChatWindow.dockableWindowData[idxW].idxRootWindow == rootWindowIndex)
        then
            -- A context menu is open, please do not perform the fade out.
            return
        end
            end 

    if (rootWindowIndex == nil)
    then
        -- Perform fade out for all windows, since none have been specifically faded in from user input
        for idxW, wnd in pairs(ChatWindow.Windows) do
			if (ChatWindow.autohide == true) then
				WindowSetAlpha ( wnd.resizeButton, wnd.windowMinAlpha)
				WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
				for idxT, tab in pairs(wnd.Tabs) do
					WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
				end
			end
            ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = true
        end
    else
        local topTabName, isTopTabNameTop
        topTabName = DockableWindowGetTopWindowName(ChatWindow.Windows[rootWindowIndex].wndName)
        -- Perform fade out for select windows, since we have been specifically faded in from user input
        for idxW, wnd in pairs(ChatWindow.Windows) do
            if (ChatWindow.dockableWindowData[idxW].idxRootWindow == 0)
            then
                -- Uninitialized window, needs to have it's root window defined
                local rootName = DockableWindowGetRootName(wnd.wndName)
                ChatWindow.dockableWindowData[idxW].idxRootWindow = WindowGetId(rootName)
            end
            if (rootWindowIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
            then
				if (ChatWindow.autohide == true) then
					WindowSetAlpha ( wnd.resizeButton, wnd.windowMinAlpha)
					WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
					for idxT, tab in pairs(wnd.Tabs) do
						WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
					end
				end
				ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = true
            end
        end
    end
end

-- OnUpdate Handler
function ChatWindow.OnUpdate( elapsedTime )
    if bDirty then
		fDirtyDelay = fDirtyDelay - elapsedTime
		if (fDirtyDelay < 0.0) then
			ChatWindow.SaveSettings()
			fDirtyDelay = 0.0
		end
    end
    local rootIndex = 0
    local updatedStatus = false
    for idxW, wnd in pairs(ChatWindow.Windows) do
        -- Only want to update everything once, we'll only check items at the root index specified
        if (rootIndex == ChatWindow.dockableWindowData[idxW].idxRootWindow)
        then
            continue
        else
            rootIndex = ChatWindow.dockableWindowData[idxW].idxRootWindow
            if (rootIndex == 0)
            then
                continue
            end
            updatedStatus = false
        end

        if (ChatWindow.dockableWindowData[rootIndex].fadeInTimer > 0 and updatedStatus == false)
        then
            ChatWindow.dockableWindowData[rootIndex].fadeInTimer = ChatWindow.dockableWindowData[rootIndex].fadeInTimer - elapsedTime
            updatedStatus = true
            if( ChatWindow.dockableWindowData[rootIndex].fadeInTimer < 0 and ChatWindow.dockableWindowData[rootIndex].isWindowAlphaMin == true) then
                ChatWindow.dockableWindowData[rootIndex].fadeInTimer = 0
                ChatWindow.dockableWindowData[rootIndex].fadeOutTimer = 0
                ChatWindow.PerformFadeIn(rootIndex)
                continue
            end
        end

        if (ChatWindow.dockableWindowData[rootIndex].fadeOutTimer > 0 and updatedStatus == false)
        then
            ChatWindow.dockableWindowData[rootIndex].fadeOutTimer = ChatWindow.dockableWindowData[rootIndex].fadeOutTimer - elapsedTime
            updatedStatus = true
            if( ChatWindow.dockableWindowData[rootIndex].fadeOutTimer < 0 and ChatWindow.dockableWindowData[rootIndex].isWindowAlphaMin == false) then
                ChatWindow.dockableWindowData[rootIndex].fadeOutTimer = 0
                ChatWindow.dockableWindowData[rootIndex].fadeInTimer = 0
                ChatWindow.PerformFadeOut(rootIndex)
                continue
            end
        end
    end
    
    -- Check the chat text buffer to see if it has been updated
    -- If so, then do the check to see if you should replace the first word with 
    -- the proper string...ie, /say -> [Say]:
    if (ChatWindowContainerTextInput.TextUpdated == true) then
        ChatWindow.DoChatTextReplacement ()
        -- Make sure to reset the var because we handled this update
        ChatWindowContainerTextInput.TextUpdated = false
    end
    
    if(ChatWindow.topWindow ~= "" and ButtonGetPressedFlag(ChatWindow.topWindow.."Tab") == false) then
		ButtonSetPressedFlag(ChatWindow.topWindow.."Tab", true)
	end
end
function ChatWindow.LoadSettings()
	bLoading = true
    -- pull C data into the chat setting vars
    Settings.LoadChatSettings()
    ChatWindow.InitRootChatTab()

    -- enable this code to reset when reloading for testing purposes
    --ChatWindow.Settings.Chat = {}

    -- remove existing tabs (except the first), necessary for reloadui to not screw things up
    for idxW, wnd in pairs(ChatWindow.Windows) do
        for idxT, tab in pairs(wnd.Tabs) do
            if idxT ~= 1 then
                ChatWindow.RemoveTab(idxW,idxT)
            end
        end
    end

    -- remove extra chat windows
    for idxW, wnd in pairs(ChatWindow.Windows) do
        if idxW ~= 1 then
            ChatWindow.RemoveTab(idxW,1)
        end
    end

    --DEBUG(L"Loading chat settings")
    -- attempt to use the saved chat settings
    if ( ChatWindow.Settings.Chat == nil )
    then
        -- DEBUG(L"Saved chat settings failed. Resetting...")
        ChatWindow.Settings.Chat = {}
    end
    
    if ( ChatWindow.Settings.Chat.Windows == nil
        or ChatWindow.Settings.Chat.Windows[1] == nil
        or ChatWindow.Settings.Chat.Windows[1].Tabs == nil
        or ChatWindow.Settings.Chat.Windows[1].Tabs[1] == nil
        or ChatWindow.Settings.Chat.Windows[1].Tabs[1].name == nil
        or ChatWindow.Settings.Chat.Windows[1].Tabs[1].name == ""
        or ChatWindow.Settings.Chat.Windows[1].Tabs[1].font == nil 
        or ChatWindow.Settings.Chat.Windows[1].Tabs[1].font == ""
        or ChatWindow.Settings.Version == nil 
        or ChatWindow.Settings.Version < ChatWindow.BaseVersion)
    then

        -- if any of those things fail, reset
        ChatWindow.Settings.Chat.Windows = {}
        ChatWindow.Settings.Chat.Windows[1] = {}
        ChatWindow.Settings.Chat.Windows[1].windowPos = {}

        --Debug.Print(L"No chat settings, loading defaults")

        -- no saved settings found, setup default chat system
        ChatWindow.SetupNewTab( 1, "Chat", 1, GetStringFromTid(ChatWindow.TID.System), "ChatWindowChatTab", "ChatWindowChatLogDisplay" )

		--------- BEGIN Set up Journal Tab ---------
		ChatWindow.Windows[2] = {}

		ChatWindow.dockableWindowData[2] = {}
		ChatWindow.dockableWindowData[2].fadeInTimer = 0
		ChatWindow.dockableWindowData[2].fadeOutTimer = 0
		ChatWindow.dockableWindowData[2].idxRootWindow = 0
		ChatWindow.dockableWindowData[2].isContextMenuShowing = false
		ChatWindow.dockableWindowData[2].isWindowAlphaMin = true
		ChatWindow.dockableWindowData[2].isUndocking = false

		local wnd = ChatWindow.Windows[2]
		wnd.Tabs = {}
		wnd.activeTab = 1
		
		local rootWindowName = "ChatWindow"
		local rootWindowIndex = WindowGetId("ChatWindow")

		if (rootWindowIndex <= 0 or rootWindowIndex > #ChatWindow.Windows or rootWindowIndex == nil)
		then
			wnd.windowMinAlpha = WINDOW_MIN_ALPHA
		else
			wnd.windowMinAlpha = ChatWindow.Windows[rootWindowIndex].windowMinAlpha
		end
		
		if (rootWindowIndex <= 0 or rootWindowIndex > #ChatWindow.Windows or rootWindowIndex == nil)
		then
			wnd.windowMaxAlpha = DEFAULT_WINDOW_MAX_ALPHA
		else
			wnd.windowMaxAlpha = ChatWindow.Windows[rootWindowIndex].windowMaxAlpha
		end

		wnd.wndName = ChatWindow.AddDockableWindow(rootWindowName)
		WindowSetId( wnd.wndName, 2 )

		-- the first tab is built-in by XML, must have name = parent+componentName
		local tabName = wnd.wndName.."ChatTab"
		local logDisplayName = wnd.wndName.."ChatLogDisplay"
		local labelName = GetStringFromTid(ChatWindow.TID.Journal)
		DockableWindowSetTabString(wnd.wndName, labelName)

		wnd.resizeButton = wnd.wndName.."ResizeButton"
		wnd.background = wnd.wndName.."Background"
		wnd.showTimestamp = false

		ChatWindow.SetupNewTab( 2, nil, 1, labelName, tabName, logDisplayName )

		for idxT, tab in pairs(wnd.Tabs) do
			WindowSetAlpha( tab.tabButton, WINDOW_MIN_ALPHA )
			WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
		end
		WindowSetAlpha( wnd.resizeButton, wnd.windowMaxAlpha )
		WindowSetAlpha( wnd.background, wnd.windowMaxAlpha )
		WindowSetAlpha( wnd.wndName.."Tab", wnd.windowMaxAlpha )
		--------- END Set up Journal Tab ---------
        
        DockableWindowSetTopWindow(ChatWindow.Windows[1].wndName,ChatWindow.Windows[1].wndName)
        ChatFiltersWindow.SetDefaultFilters()
        for idxT, tab in pairs(ChatWindow.Windows[1].Tabs) do
            WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
        end
        --WindowSetShowing(ChatWindow.Windows[1].wndName, false)
    else
        -- DEBUG(L"Loading windows, total # ="..#ChatWindow.Settings.Chat.Windows)
        
        if( ChatWindow.Settings.windowLocked ~= nil ) then
            ChatWindow.windowLocked = ChatWindow.Settings.windowLocked
        end
        
        if( ChatWindow.Settings.autohide ~= nil ) then
            ChatWindow.autohide = ChatWindow.Settings.autohide
        end
        
        local actualWndIdx = 0   -- we skip unloadable windows, track where we are in the actual array
        local savedWindowNames = {}

        for savedWndIdx, savedWnd in pairs(ChatWindow.Settings.Chat.Windows) do
            if savedWndIdx > ChatWindow.Settings.Chat.numWindows then
                -- DEBUG(L"Chat Window data out of sync.")
                continue
            end

            --DEBUG(L"ChatWindow.Settings.Chat.Windows[savedWndIdx].windowName: "..StringToWString(ChatWindow.Settings.Chat.Windows[savedWndIdx].windowName))
            --DEBUG(L"ChatWindow.Settings.Chat.Windows[savedWndIdx].rootName: "..StringToWString(ChatWindow.Settings.Chat.Windows[savedWndIdx].rootName))
            -- verify this window is loadable and not totally messed up (must have a valid first tab)
            if ( savedWnd.Tabs == nil
                or savedWnd.Tabs[1] == nil
                or savedWnd.Tabs[1].name == nil
                or savedWnd.Tabs[1].name == ""
                or savedWnd.Tabs[1].font == nil
                or savedWnd.Tabs[1].font == "" ) then
                continue
            end

            --Debug.Print("Loading chat wnd "..tostring(savedWndIdx))

            if savedWndIdx > 1 then
                local tempLastChatWindowName = lastChatWindowName
                lastChatWindowName = nil
                skipSave = true
                ChatWindow.OnNewWindow()
                skipSave = false
                lastChatWindowName = tempLastChatWindowName
            end

            actualWndIdx = actualWndIdx + 1
            ChatWindow.LoadChatWindowSettings( ChatWindow.Windows[actualWndIdx].wndName, savedWnd.windowName, savedWnd )
            savedWindowNames[actualWndIdx] = {}
            savedWindowNames[actualWndIdx].savedName = savedWnd.windowName
            savedWindowNames[actualWndIdx].rootName = savedWnd.rootName
            savedWindowNames[actualWndIdx].showTimestamp = savedWnd.showTimestamp
            DockableWindowSetTabString(ChatWindow.Windows[actualWndIdx].wndName, savedWnd.tabName)

            --Debug.Print("Loading tabs, total # ="..tostring(#savedWnd.Tabs))
            local actualTabIdx = 0
            for savedTabIdx, savedTab in pairs(savedWnd.Tabs) do
                -- make sure our loading doesn't exceed what we think is there
                if savedTabIdx > savedWnd.numTabs then
                    --Debug.Print("Chat Tab data out of sync.")
                    continue
                end

                -- ignore tabs that forgot their name
                if savedTab.name == nil 
                    or savedTab.name == "" then
                    --Debug.Print("Chat Tab data badly formatted")
                    continue
                end

                actualTabIdx = actualTabIdx + 1
                --Debug.Print("Loading chat tab "..tostring(savedTabIdx).." "..tostring(savedTab.name))

                local logDisplayName = " "
                -- tab 1 is the special system chat tab, it is already created by XML and just nees configured
                if savedTabIdx == 1 then
                    -- use the proper names here
                    if savedWndIdx == 1 then
                        ChatWindow.SetupNewTab( actualWndIdx, nil, 1, StringToWString(savedTab.name), "ChatWindowChatTab", "ChatWindowChatLogDisplay" )
                        logDisplayName = "ChatWindowChatLogDisplay"
                    else
                        local tab = ChatWindow.Windows[actualWndIdx].Tabs[actualTabIdx]
                        logDisplayName = tab.tabWindow
                        tab.labelName = StringToWString(savedTab.name)
                    end
                else
                    local newTab = ChatWindow.CreateNewTab( actualWndIdx, savedTab.name )
                    ChatWindow.SetupNewTab( actualWndIdx, nil, unpack(newTab) )
                    logDisplayName = newTab[4]
                end

                if savedTab.font ~= nil
                    and savedTab.font ~= "" then
                    LogDisplaySetFont( logDisplayName, savedTab.font )
                end

                -- apply filters
                for channelId, msgTypeData in pairs( ChatSettings.Channels ) do
                    local enabled = false
                    if ( savedTab.Filters ~= nil and savedTab.Filters[ channelId ] ~= nil ) then
                        enabled = msgTypeData.isOnAlways or savedTab.Filters[ channelId ]
                    elseif ( savedTab.defaultLog ~= nil ) then
                        enabled = (msgTypeData.isOnAlways or msgTypeData.isOnJournal) and msgTypeData.logName == savedTab.defaultLog
                    end
                    LogDisplaySetFilterState( logDisplayName, msgTypeData.logName, msgTypeData.id, enabled )
                end
            end -- for each tab

			savedWindowNames[actualWndIdx].windowMinAlpha = savedWnd.windowMinAlpha
            savedWindowNames[actualWndIdx].windowMaxAlpha = savedWnd.windowMaxAlpha
            ChatWindow.ShowTab( actualWndIdx, 1 )
        end   -- for each wnd

        local rootWindows = {}
        local rootWindowsIndex = {}
        local rootIndex = 1
        for idxI=1, #ChatWindow.Windows do
            if (rootWindows[savedWindowNames[idxI].rootName] == nil) then
                rootWindows[savedWindowNames[idxI].rootName] = savedWindowNames[idxI].rootName
                rootWindowsIndex[rootIndex] = savedWindowNames[idxI].rootName
                rootIndex = rootIndex + 1
            end
            -- Set ALL window's variables
            ChatWindow.Windows[idxI].showTimestamp = savedWindowNames[idxI].showTimestamp
            ChatWindow.Windows[idxI].windowMinAlpha = savedWindowNames[idxI].windowMinAlpha
            ChatWindow.Windows[idxI].windowMaxAlpha = savedWindowNames[idxI].windowMaxAlpha
            
            if (savedWindowNames[idxI].savedName ~= savedWindowNames[idxI].rootName) then
                WindowSetShowing(ChatWindow.Windows[idxI].wndName, false)
                
                for idxJ=1, #ChatWindow.Windows do
                    if (savedWindowNames[idxJ].savedName == savedWindowNames[idxI].rootName) then
                        DockableWindowDock(ChatWindow.Windows[idxJ].wndName, ChatWindow.Windows[idxI].wndName)
                        iOffset = DockableWindowGetTabOffset(ChatWindow.Windows[idxJ].wndName)
                        --DEBUG(L"RootWindow: "..StringToWString(ChatWindow.Windows[idxJ].wndName)..L" with offset: "..iOffset)
                        break
                    end
                end
            end
        end
        for idxI=1, #rootWindowsIndex do
            DockableWindowSetTopWindow(rootWindows[rootWindowsIndex[idxI]],rootWindows[rootWindowsIndex[idxI]])
            for idxT, tab in pairs(ChatWindow.Windows[idxI].Tabs) do
                --DEBUG(L"TabWindowName:"..StringToWString(tab.tabWindow))
                WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
            end
        end
        
        if( ChatWindow.Settings.topWindow ~= nil ) then
            ChatWindow.topWindow = ChatWindow.Settings.topWindow
            local rootName = DockableWindowGetRootName(ChatWindow.topWindow)
			DockableWindowSetTopWindow(rootName, ChatWindow.topWindow)
			ButtonSetPressedFlag(ChatWindow.topWindow.."Tab",true)
        end
    end
    -- adding artificial delay to the first save because the window doesn't update it's offset properly right away
    -- this might have something to do with the queueing of window creations from LUA
    fDirtyDelay = ChatWindow.SAVE_DELAY
	bDirty = true
	bLoading = false
	-- update the resize buttons now that we have finished loading or creating the chat windows
	ChatWindow.UpdateResizeButtons()
end


function ChatWindow.SaveSettings()
	bDirty = false
    --Debug.Print("Save Called")
    -- clear old settings
    ChatWindow.Settings.Chat.Windows = {}
    ChatWindow.Settings.Version = ChatWindow.CurrentVersion
    
    ChatWindow.Settings.windowLocked = ChatWindow.windowLocked
    ChatWindow.Settings.autohide = ChatWindow.autohide
    ChatWindow.Settings.topWindow = ChatWindow.topWindow
    
    local settingsChanged = false

    for idxW, wnd in pairs(ChatWindow.Windows) do
        -- DEBUG(L"Save wnd "..idxW)

        ChatWindow.Settings.Chat.Windows[idxW] = {}
        ChatWindow.Settings.Chat.Windows[idxW].windowName = wnd.wndName
        ChatWindow.Settings.Chat.Windows[idxW].rootName = DockableWindowGetRootName(wnd.wndName)
        ChatWindow.Settings.Chat.Windows[idxW].tabName = DockableWindowGetTabString(wnd.wndName)
        ChatWindow.Settings.Chat.Windows[idxW].showTimestamp = wnd.showTimestamp
        ChatWindow.Settings.Chat.Windows[idxW].windowMinAlpha = wnd.windowMinAlpha
        ChatWindow.Settings.Chat.Windows[idxW].windowMaxAlpha = wnd.windowMaxAlpha
        ChatWindow.Settings.Chat.Windows[idxW].Tabs = {}
        local saveWnd = ChatWindow.Settings.Chat.Windows[idxW]
        
        for idxT, tab in pairs(wnd.Tabs) do
            -- DEBUG(L"Save tab "..idxT)

            saveWnd.Tabs[idxT] = {}
            local saveTab = saveWnd.Tabs[idxT]

            saveTab.name = WStringToString( tab.labelName )
            saveTab.font = LogDisplayGetFont( tab.tabWindow )
            saveTab.defaultLog = tab.defaultLog

            saveTab.Filters = {}
            for channelId, channel in pairs(ChatSettings.Channels) do
                local enabled = LogDisplayGetFilterState( tab.tabWindow, channel.logName, channelId )
                saveTab.Filters[ channelId ] = enabled
            end
        end
        saveWnd.numTabs = #saveWnd.Tabs
		-- Window Size
		saveWnd.sizeX, saveWnd.sizeY = WindowGetDimensions( wnd.wndName)

		-- Window Position - Conver the Window Pos into general parameters for the screen
		-- based on the window's scale.
		local screenX, screenY = GetScreenResolution()
		local posX, posY = WindowGetScreenPosition( wnd.wndName )
		saveWnd.posX = posX / screenX
		saveWnd.posY = posY / screenY

		-- Movable
		saveWnd.movable = WindowGetMovable( wnd.wndName )

		-- Alpha
		saveWnd.alpha = WindowGetAlpha( wnd.wndName )

		local wszMovable
		if saveWnd.movable then
			wszMovable = L"true"
		else
			wszMovable = L"false"
		end
		--DEBUG(L"SAVING...")
		--DEBUG(StringToWString(wnd.wndName)..L": offset:("..saveWnd.posX..L","..saveWnd.posY..L") size:("..saveWnd.sizeX..L","..saveWnd.sizeY..L") movable: "..wszMovable..L" alpha: "..saveWnd.alpha)
        settingsChanged = true
    end
    
    ChatWindow.Settings.Chat.numWindows = #ChatWindow.Settings.Chat.Windows
    
    -- BroadcastEvent probably doesn't need to be called here, because the loop handles calling
    -- WindowUtils.SaveSettings (which ends up broadcasting the user-settings event).
    -- But just in case it really really needs to be called here, I'll leave in the call...but eliminate
    -- the redundant broadcast with the use of the "settingsChanged" var.
    
    if (settingsChanged == false)
    then
        -- push the new values to c++
		UserSettingsChanged()
    end
end

-- OnShutdown Handler
function ChatWindow.Shutdown()
    ChatWindow.SaveSettings()
    
    -- Retrieve the history (this preserves it across logging in/out)
    GameData.ChatData.history = TextEditBoxGetHistory("ChatWindowContainerTextInput")
end

----------------------------------------------------------------
-- Right-click context menu
----------------------------------------------------------------

function ChatWindow.SpawnFontSelectionMenu()
    local id = WindowGetId( ChatWindow.GetCurrentTabName() )
    local wndNum = ChatWindow.GetCurrentTabID()
    EA_Window_ContextMenu.CreateContextMenu("", EA_Window_ContextMenu.CONTEXT_MENU_3)
    local size = #ChatSettings.Fonts
    for idx=1, size
    do
       local _, y = LabelGetTextDimensions( "ChatWindowContextFontMenuItem"..idx.."Label" )
       EA_Window_ContextMenu.AddUserDefinedMenuItem("ChatWindowContextFontMenuItem"..idx, EA_Window_ContextMenu.CONTEXT_MENU_3)
       if (LogDisplayGetFont(ChatWindow.Windows[wndNum].Tabs[1].tabWindow) == ChatSettings.Fonts[idx].fontName)
       then
            WindowSetShowing("ChatWindowContextFontMenuItem"..idx.."Check", true)
       else
            WindowSetShowing("ChatWindowContextFontMenuItem"..idx.."Check", false)
       end
    end
    EA_Window_ContextMenu.Finalize(EA_Window_ContextMenu.CONTEXT_MENU_3)
end

function ChatWindow.HideFontSelectionMenu()
    local winName = "EA_Window_ContextMenu3"
    if (string.sub( SystemData.MouseOverWindow.name, 1, string.len(winName)) == winName or 
       string.sub( WindowGetParent( SystemData.MouseOverWindow.name ), 1, string.len(winName) ) == winName)
    then
        return
    else
        -- Make another check
        winName = "ChatWindowContextFontSelection"
        if (string.sub( SystemData.MouseOverWindow.name, 1, string.len(winName)) == winName or 
            string.sub( WindowGetParent( SystemData.MouseOverWindow.name ), 1, string.len(winName) ) == winName) 
        then
            return
        else
            EA_Window_ContextMenu.Hide(EA_Window_ContextMenu.CONTEXT_MENU_3)
        end
    end
end

function ChatWindow.OnSelectTab()
    --Debug.Print("ChatWindow.OnSelectTab: "..SystemData.ActiveWindow.name)
    ChatWindow.HideMenu() 
    ChatWindow.OnCancelRename()
 
    -- get root index
    local curRootIndex = 1
    for idxW, wnd in pairs(ChatWindow.Windows) do
        for idxT, tab in pairs(wnd.Tabs) do
            tabButton = wnd.wndName.."Tab"
            if( tabButton==SystemData.ActiveWindow.name ) then
                curRootIndex = ChatWindow.dockableWindowData[idxW].idxRootWindow
                ChatWindow.topWindow = wnd.wndName
            end            
        end
    end   
    
    for idxW, wnd in pairs(ChatWindow.Windows) do
        -- only modify windows with the same root window
        if( ChatWindow.dockableWindowData[idxW].idxRootWindow == curRootIndex ) then
            for idxT, tab in pairs(wnd.Tabs) do
                tabButton = wnd.wndName.."Tab"
                ButtonSetPressedFlag(tabButton,tabButton==SystemData.ActiveWindow.name)
            end
        end
    end    
end

function ChatWindow.SetActiveWindow()
    -- sets the active window to the owner of the currently pointed-at tab
    ChatWindow.activeWindow = 1
    for idxW, wnd in pairs(ChatWindow.Windows) do
        for idxT, tab in pairs(wnd.Tabs) do
            if tab.tabButton == SystemData.ActiveWindow.name then
                ChatWindow.activeWindow = idxW
                return
            end
        end
    end
end

function ChatWindow.ShowTab( wndNum, tabNum )
    ChatWindow.Windows[wndNum].activeTab = tabNum

    for idx, tab in pairs(ChatWindow.Windows[wndNum].Tabs) do
        ButtonSetPressedFlag( tab.tabButton, idx == tabNum )
        --WindowSetShowing( tab.tabWindow, idx == tabNum )
    end
    --ChatWindow.UpdateNewTextAlert(wndNum)
end

function ChatWindow.Print (text, channelId)
    local validId = ChatSettings.Channels[SystemData.ChatLogFilters.SAY].id
    local logName = "Chat"

    if (channelId and ChatSettings.Channels[channelId] ~= nil) then
        validId = ChatSettings.Channels[channelId].id
        logName = ChatSettings.Channels[channelId].logName;
    end

    TextLogAddEntry (logName, validId, text)
end

--[[
    Convenience function for switching chat channels from both the event handler
    and arbitrary windows that need to pass existing text to a new channel.
]]
function ChatWindow.SwitchChannelWithExistingText (existingText)
    
    -- Set the Focus to the text input
    WindowSetShowing( "ChatWindowContainer", true )
    WindowSetShowing( "ChatWindowContainerTextInput", true )
    WindowAssignFocus( "ChatWindowContainerTextInput", true )
    
    -- if the window is faded to minimum, and is not in the midst of fading in, fade it in immediately.
    -- This is only tied to the Chat Dockable Window
    if (ChatWindow.dockableWindowData[1].isWindowAlphaMin == true and ChatWindow.dockableWindowData[1].fadeInTimer == 0 and ChatWindow.windowLocked == false)
    then
        -- Chat window should be faded in
        ChatWindow.PerformFadeIn(1)
        ChatWindow.dockableWindowData[1].fadeOutTimer = 0
    end
    
    if (existingText == nil) then
        existingText = L"";
    end
    
    -- Set the default channel to Say or the previous channel
    if (curChannel == nil and prevChannel == nil) then
        ChatWindow.SwitchToChatChannel (SystemData.ChatLogFilters.SAY, ChatSettings.Channels[SystemData.ChatLogFilters.SAY].labelText, existingText)
    elseif (prevChannel ~= nil) then
        if (prevChannel == SystemData.ChatLogFilters.TELL_SEND and whisperTarget ~= nil) then
            ChatWindow.SwitchToChatChannel (prevChannel, ChatWindow.FormatWhisperPrompt (whisperTarget), existingText)
        elseif (prevChannel == SystemData.ChatLogFilters.GLOBAL_CHAT) then
            ChatWindow.SwitchToGChatSelectedChannel(existingText)
        else
            ChatWindow.SwitchToChatChannel (prevChannel, ChatSettings.Channels[prevChannel].labelText, existingText)
        end
    end
end

--[[
    Event Handler for pressing a chat activation key (enter or slash)
]]
function ChatWindow.OnEnterChatText()   
    if( IsTextInputWindowActive() == false ) then
        ChatWindow.SwitchChannelWithExistingText (L"");    
    end
end

-- ChatWindowContainerTextInput OnKeyEnter Handler
function ChatWindow.OnKeyEnter()

    local chatChannel = L""
    local chatText = ChatWindowContainerTextInput.Text
    
    if (curChannel ~= nil) then
    
        -- This is the channel that the text will go to...
        chatChannel = ChatSettings.Channels[curChannel].serverCmd
        
        if (curChannel == SystemData.ChatLogFilters.TELL_SEND) then
            
            if (whisperTarget ~= nil) then
                -- Unless there is a whisper target...in which case that needs to be appended to the channel
                chatChannel    = ChatSettings.Channels[curChannel].serverCmd..L" "..whisperTarget
            else               
                -- But if there is no whisper target, and you're in the tell channel, don't send anything.
                chatText = L""
            end
            
        end        
        
    end

    --Debug.Print(L"ChatWindow.OnKeyEnter: text="..chatChannel..L" "..chatText)
    SendChat(chatChannel,chatText)
    
    ChatWindow.ResetTextBox ()
    
    -- Hide the Text Input Window
    WindowAssignFocus( "ChatWindowContainerTextInput", false )
    WindowSetShowing( "ChatWindowContainer", false )

    -- if the window is faded to maximum, and is not in the midst of fading out, start the fade out timer.
    if (ChatWindow.dockableWindowData[1].isWindowAlphaMin == false and ChatWindow.dockableWindowData[1].fadeOutTimer == 0)
    then
        ChatWindow.dockableWindowData[1].fadeOutTimer = ChatWindow.FADE_OUT_DELAY*2
    end
end

-- ChatWindowContainerTextInput OnKeyEscape Handler
function ChatWindow.OnKeyEscape()

    ChatWindow.ResetTextBox ()

    -- Hide the Text Input Window
    WindowAssignFocus( "ChatWindowContainerTextInput", false )
    WindowSetShowing( "ChatWindowContainer", false )

    -- if the window is faded to maximum, and is not in the midst of fading out, start the fade out timer.
    if (ChatWindow.dockableWindowData[1].isWindowAlphaMin == false and ChatWindow.dockableWindowData[1].fadeOutTimer == 0)
    then
        ChatWindow.dockableWindowData[1].fadeOutTimer = ChatWindow.FADE_OUT_DELAY
    end
end

-- ChatWindowContainerTextInput OnKeyTab Handler
-- Cycles through people who just whispered you
-- IF you're in the /whisper channel
function ChatWindow.OnKeyTab()

    if (curChannel == SystemData.ChatLogFilters.TELL_SEND) then
    
        --DEBUG (L"ChatWindow.OnKeyTab called and it's checking things!");
    
        replyIndex = replyIndex + 1;
        
        if (replyIndex > SystemData.UserInput.ReplyListSize or SystemData.UserInput.ReplyToPlayerName[replyIndex] == L"") then
            replyIndex = 1;
        end
        
        local newTarget = SystemData.UserInput.ReplyToPlayerName[replyIndex];
        
        if (newTarget ~= L"") then
            prevChannel     = SystemData.ChatLogFilters.TELL_SEND;
            whisperTarget   = newTarget;
            ChatWindow.SwitchChannelWithExistingText (ChatWindowContainerTextInput.Text);
        end
    end
end

function ChatWindow.ResetTextBox ()

    -- Reanchor the Text Box
    WindowClearAnchors("ChatWindowContainerTextInput")
    WindowAddAnchor("ChatWindowContainerTextInput", "topright", "ChatWindowContainerChannelLabel", "topleft", 2, -6)
    WindowAddAnchor("ChatWindowContainerTextInput", "bottomright", "ChatWindowContainer", "bottomright", 0, 2)
    
    -- Clear the Text
    TextEditBoxSetText("ChatWindowContainerTextInput", L"")  

    -- Reset the color to white
    TextEditBoxSetTextColor ("ChatWindowContainerTextInput", 255, 255, 255)
    
    -- Reset all the label stuff
    LabelSetTextColor ("ChatWindowContainerChannelLabel", 255, 255, 255)
                                                 
    LabelSetText ("ChatWindowContainerChannelLabel", L"")
    
    ChatWindow.UpdateCurrentChannel (nil)

end

function ChatWindow.UpdateCurrentChannel (icurChannel)
    prevChannel = curChannel
    curChannel  = icurChannel
end

function ChatWindow.OnLock()
    DockableWindowSetMovable( EA_Window_ContextMenu.activeWindow, false )
    ChatWindow.UpdateResizeButtons()
	bDirty = true
end

function ChatWindow.OnUnlock()
    DockableWindowSetMovable( EA_Window_ContextMenu.activeWindow, true )
    ChatWindow.UpdateResizeButtons()
	bDirty = true
end

function ChatWindow.UpdateResizeButtons()
    for idxW, wnd in pairs(ChatWindow.Windows) do
		if wnd.wndName ~= nil then
			local szResizeName = wnd.wndName.."ResizeButton"
			local buttonAlpha = WINDOW_MIN_ALPHA
			if (WindowGetMovable(wnd.wndName)) then
				buttonAlpha = wnd.windowMaxAlpha
			end
			WindowSetAlpha(szResizeName, buttonAlpha)
		end
    end
end

function ChatWindow.InitializeChannelMenuSelectionWindow()
    CreateWindow( "ChatChannelSelectionWindow", false )
    
    -- Say channel
    local channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.SAY ]
    WindowSetId( "ChatChannelSelectionWindowSayButton", SystemData.ChatLogFilters.SAY)
    ButtonSetText( "ChatChannelSelectionWindowSayButton", L"/Say" ) 
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Yell channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.YELL ]
    WindowSetId( "ChatChannelSelectionWindowYellButton", SystemData.ChatLogFilters.YELL)
    ButtonSetText("ChatChannelSelectionWindowYellButton", L"/Yell" )
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Guild channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.GUILD ]
    WindowSetId( "ChatChannelSelectionWindowGuildButton", SystemData.ChatLogFilters.GUILD )
    ButtonSetText("ChatChannelSelectionWindowGuildButton", L"/Guild" )
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Party channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.PARTY ]
    WindowSetId( "ChatChannelSelectionWindowPartyButton", ChatSettings.Channels[SystemData.ChatLogFilters.PARTY].id )
    ButtonSetText("ChatChannelSelectionWindowPartyButton", L"/Party" )
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Alliance channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.ALLIANCE ]
    WindowSetId( "ChatChannelSelectionWindowAllianceButton", ChatSettings.Channels[SystemData.ChatLogFilters.ALLIANCE].id )
    ButtonSetText("ChatChannelSelectionWindowAllianceButton", L"/Alliance" )
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Chat channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.CUSTOM ]
    WindowSetId( "ChatChannelSelectionWindowChatButton", SystemData.ChatLogFilters.CUSTOM)
    ButtonSetText("ChatChannelSelectionWindowChatButton", L"/Chat (Channel)" )
    ButtonSetTextColor("ChatChannelSelectionWindowChatButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowChatButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowChatButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowChatButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)

    ChatWindow.firstGChatSelect = true
    ChatWindow.OnGChatRosterUpdate()    
end

function ChatWindow.UpdateAllChannelColors()
    -- Say Channel
    local channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.SAY ]
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Shout Channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.YELL ]
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Guild Channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.GUILD ]
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Party Channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.PARTY ]
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Warband Channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.ALLIANCE ]
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("ChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
end

function ChatWindow.OnOpenChannelMenu()
	Tooltips.ClearTooltip()

    if (WindowGetShowing("ChatChannelSelectionWindow") == true)
    then
        WindowSetShowing("ChatChannelSelectionWindow", false)
        WindowAssignFocus( "ChatChannelSelectionWindow", false )
    else
        WindowClearAnchors( "ChatChannelSelectionWindow" )
        WindowAddAnchor( "ChatChannelSelectionWindow", "bottomright", "ChatWindowInputTextButton", "bottomleft", 0, 0 )    
        WindowSetShowing("ChatChannelSelectionWindow", true)
        WindowSetShowing( "ChatChannelSelectionWindowSelection", false )
        WindowAssignFocus( "ChatChannelSelectionWindow", true )
    end
end

function ChatWindow.OnOpenTabMenu()
	--Debug.Print("ChatWindow.OnOpenTabMenu")
	Tooltips.ClearTooltip()
    
    EA_Window_ContextMenu.CreateContextMenu("ChatWindowInputTextButton", EA_Window_ContextMenu.CONTEXT_MENU_1)
    
    local lockWindowLabel = GetStringFromTid(ChatWindow.TID.LockWindow)
    if( ChatWindow.windowLocked == true ) then
        lockWindowLabel = GetStringFromTid(ChatWindow.TID.UnlockWindow)
    end    
    
    EA_Window_ContextMenu.AddMenuItem(lockWindowLabel, ChatWindow.OnLockButtonClicked, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    ButtonSetPressedFlag("ChatWindowContextAutoHideButton", ChatWindow.autohide)
    EA_Window_ContextMenu.AddUserDefinedMenuItem("ChatWindowContextAutoHide", EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.SetOpacity), ChatWindow.OnWindowOptionsSetAlpha, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.TextColors), ChatWindow.OnViewChatOptions, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    
    EA_Window_ContextMenu.AddUserDefinedMenuItem("ChatWindowTabMenuDivider", EA_Window_ContextMenu.CONTEXT_MENU_1)
    
	for idxW, wnd in pairs(ChatWindow.Windows) do
		for idxT, tab in pairs(wnd.Tabs) do
			EA_Window_ContextMenu.AddMenuItem(tab.labelName, ChatWindow.OnTabSelected, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1, idxW)
		end
	end
	
	anchor = 
	{
		XOffset = 0,
        YOffset = 0,
        Point = "bottomright",
        RelativePoint = "bottomleft",
        RelativeTo = "ChatWindowInputTextButton",
    }
	
    EA_Window_ContextMenu.Finalize(EA_Window_ContextMenu.CONTEXT_MENU_1,anchor)
end

function ChatWindow.OnTabSelected(param)
	local rootName = DockableWindowGetRootName(ChatWindow.Windows[param].wndName)
	DockableWindowSetTopWindow(rootName, ChatWindow.Windows[param].wndName)
	ChatWindow.topWindow = ChatWindow.Windows[param].wndName
end

function ChatWindow.UpdateMenuSelection()
    local parentName = WindowGetParent( SystemData.ActiveWindow.name )
    WindowClearAnchors( parentName.."Selection" )
    WindowAddAnchor( parentName.."Selection", "topleft", SystemData.ActiveWindow.name, "topleft", -6, -4 )
    WindowAddAnchor( parentName.."Selection", "bottomright", SystemData.ActiveWindow.name, "bottomright", -8, 4 )
    WindowSetShowing( parentName.."Selection", true )
end
function ChatWindow.HideChannelSelectionMenu()
    WindowAssignFocus( "ChatChannelSelectionWindow", false )
    WindowSetShowing("ChatChannelSelectionWindow", false)
end
function ChatWindow.SwitchToSelectedChannel()
    local windowId = WindowGetId(SystemData.ActiveWindow.name)
    local chatChannelId = ChatSettings.Channels[windowId].id
    ChatWindow.SwitchToChatChannel(chatChannelId, ChatSettings.Channels[chatChannelId].labelText)
    ChatWindow.UpdateCurrentChannel(chatChannelId)
    -- Show the Text Input Window and Hide the menu
    WindowAssignFocus( "ChatChannelSelectionWindow", false )
    WindowSetShowing( "ChatWindowContainer", true )
    WindowAssignFocus( "ChatWindowContainerTextInput", true )
    WindowSetShowing("ChatChannelSelectionWindow", false)
    
    -- if the window is faded to minimum, and is not in the midst of fading in, fade it in immediately.
    if (ChatWindow.dockableWindowData[1].isWindowAlphaMin == true and ChatWindow.dockableWindowData[1].fadeInTimer == 0)
    then
        -- Chat Window should be faded in
        ChatWindow.PerformFadeIn(1)
        ChatWindow.dockableWindowData[1].fadeOutTimer = 0
    end
end

function ChatWindow.SwitchToGChatSelectedChannel(existingText)
    
    if (existingText == nil) then
        existingText = L"";
    end

    local windowId = WindowGetId(SystemData.ActiveWindow.name)       
    local chatChannelId =  SystemData.ChatLogFilters.GLOBAL_CHAT
    WindowData.GChatIndex = ComboBoxGetSelectedMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo")
    
    if((WindowData.GChatIndex <= 0) or (WindowData.GChatCount == 0))then
        return
    end
    Debug.Print("SwitchToGChatSelectedChannel("..tostring(WindowData.GChatIndex)..") Before")
    if(ChatWindow.firstGChatSelect)then
        WindowData.GChatIndex = WindowData.GChatIndex - 1
        ChatWindow.firstGChatSelect = false
        ChatWindow.OnGChatRosterUpdate()         
    end    
    Debug.Print("SwitchToGChatSelectedChannel("..tostring(WindowData.GChatIndex)..") After")
    
    local friendName = L"["..towstring(WindowData.GChatNameList[WindowData.GChatIndex])..L"]:"
    local friendPresence = WindowData.GChatPresenceList[WindowData.GChatIndex]
    
    ChatWindow.SwitchToChatChannel(chatChannelId, friendName, existingText)
    ChatWindow.UpdateCurrentChannel(chatChannelId)
    -- Show the Text Input Window and Hide the menu
    WindowAssignFocus( "ChatChannelSelectionWindow", false )
    WindowSetShowing( "ChatWindowContainer", true )
    WindowAssignFocus( "ChatWindowContainerTextInput", true )
    WindowSetShowing("ChatChannelSelectionWindow", false)
    
    -- if the window is faded to minimum, and is not in the midst of fading in, fade it in immediately.
    if (ChatWindow.dockableWindowData[1].isWindowAlphaMin == true and ChatWindow.dockableWindowData[1].fadeInTimer == 0)
    then
        -- Chat Window should be faded in
        ChatWindow.PerformFadeIn(1)
        ChatWindow.dockableWindowData[1].fadeOutTimer = 0
    end

    GChatRoster.SelectActiveFriend(WindowData.GChatIndex)
end

function ChatWindow.ToggleInputText()

    if( WindowGetShowing( "ChatWindowContainer") == true )  then
        ChatWindow.OnKeyEscape()
    else
        ChatWindow.OnEnterChatText()    
    end
end

function ChatWindow.UpdateNewTextAlert( wndNum )
	--show overhead message if it's attached to something
	if ( (SystemData.Settings.Interface.OverheadChat or SystemData.TextAlwaysShow) and SystemData.TextSourceID ~= -1 ) then
		OverheadText.ShowOverheadText()
	end    
end

function ChatWindow.ScrollToBottom( windowId )
    if (windowId == 0) then
        windowId = WindowGetId( SystemData.ActiveWindow.name )
    end
    local logDisplay = ChatWindow.Windows[ windowId ].Tabs[ 1 ].tabWindow
    LogDisplayScrollToBottom( logDisplay )
    --ChatWindow.UpdateNewTextAlert( windowId )
end

-- Window Resizing...

function ChatWindow.OnResizeBegin( flags, x, y )                                                                          
    -- Start resize process
    local wnd = GetMouseOverChatWindow()
    WindowUtils.BeginResize( wnd.wndName, "bottomleft", 300, 200, false, nil )
end

-- Hot Spots
-- DAB TODO: Support hotspots
function ChatWindow.OnHotSpotMouseOver( hotSpotText, type, value )

end

function ChatWindow.UpdateChatSettings()

    -- Set the fade settings
    local visibleTime = 0
    if( SystemData.Settings.Chat.fadeText ) then
        visibleTime = SystemData.Settings.Chat.visibleTime
    end
    
    for _, TabTables in pairs(ChatWindow.Windows)
    do
        for TabIndex = 1, TabTables.numTabs
        do
            LogDisplaySetTextFadeTime( TabTables.Tabs[TabIndex].tabWindow, visibleTime )
        end
    end
    
    ChatWindow.ResetScrollLimits()
end

function ChatWindow.ResetScrollLimits()

    for _, TabTables in pairs(ChatWindow.Windows)
    do
        for TabIndex = 1, TabTables.numTabs
        do
            -- There should be a better record of what logs have been added to these log displays.
            LogSetLimit( TabTables.Tabs[TabIndex].tabWindow, SystemData.Settings.Chat.scrollLimit )
            LogSetLimit( TabTables.Tabs[TabIndex].tabWindow, SystemData.Settings.Chat.scrollLimit )
        end
    end

end

function ChatWindow.DoChatTextReplacement ()  
    
    local spaceIdx      = nil
    local restOfLine    = nil
    
    spaceIdx = wstring.find (ChatWindowContainerTextInput.Text, L" ", 1)

    -- Make sure spaceIdx is not 1 so that you can type instructions on how to
    -- type slash commands to other people...otherwise, this will continue to try parsing
    -- slash-commands even if you insert a bunch of spaces...
    if (spaceIdx ~= nil and spaceIdx ~= 1) then
                
        local firstWord = wstring.sub (ChatWindowContainerTextInput.Text, 1, spaceIdx)        
        restOfLine      = wstring.sub (ChatWindowContainerTextInput.Text, spaceIdx + 1)
        
        -- Make sure that the first word begins with a /
        -- Then check to see if you typed a slash command that will switch your channel
        if (wstring.find (firstWord, L"/", 1) ~= 1) then return end
        
        --DEBUG (L"You typed: ["..firstWord..L"], looking in all channels for that command...");
                
        for ixChannel, curChannel in pairs (ChatSettings.Channels) do           
            if (IsSlashCommandInChannel (firstWord, curChannel)) then
            
                -- This is the one special case that I can think of...it needs two params (/tell <name>)
                if (ixChannel == SystemData.ChatLogFilters.TELL_SEND) then
                    ChatWindow.HandleTellCommand (ChatWindowContainerTextInput.Text, firstWord, spaceIdx, restOfLine)
                elseif (ifirstWord == c_REPLY_COMMAND..L" " and SystemData.UserInput.ReplyToPlayerName[replyIndex] ~= L"") then
                    -- Don't go into reply mode if nobody msg'd you yet...
                    ChatWindow.HandleTellCommand (ChatWindowContainerTextInput.Text, firstWord, spaceIdx, restOfLine)
                elseif (ixChannel == SystemData.ChatLogFilters.GLOBAL_CHAT) then
                    ChatWindow.SwitchToGChatSelectedChannel()
                else
                    -- Otherwise it's a regular channel, no crazy arguments...just do the switch
                    ChatWindow.SwitchToChatChannel (ixChannel, curChannel.labelText, restOfLine)
                end
        
                return
                
            end
        end
    end
       
end

function ChatWindow.HandleTellCommand (itext, ifirstWord, ispaceIdx, iexistingText)

    local cursorPos     = ChatWindowContainerTextInput.CursorPos
    local textToExamine = wstring.sub (itext, 1, cursorPos)
    
    local space2Idx     = nil 
    local whisperPrompt = nil
    local sendTell      = false
    
    if (cursorPos > ispaceIdx + 1) then
        space2Idx = wstring.find (textToExamine, L" ", ispaceIdx + 1)
    end
    
    if ((space2Idx ~= nil) and (ifirstWord ~= c_TELL_TARGET_COMMAND)) then
    
        whisperPrompt   = ChatWindow.FormatWhisperPrompt (wstring.sub (itext, ispaceIdx + 1, space2Idx - 1))
        iexistingText   = wstring.sub (itext, cursorPos + 1)
        sendTell        = true

    elseif (ifirstWord == c_TELL_TARGET_COMMAND..L" ") then
        -- (/tt in english): Doing the same replacement as the regular tell command
        -- using the player's current target as the name
           
        whisperPrompt   = ChatWindow.FormatWhisperPrompt (GameData.Player.Target.name)
        sendTell        = true

    elseif (ifirstWord == c_REPLY_COMMAND..L" " and SystemData.UserInput.ReplyToPlayerName[replyIndex] ~= L"") then
        -- (/r in english): Switches to reply mode and currently replies to just the
        -- last person who whispered you.  FIXME: Need to add tab-cycling at some point.
        
        whisperPrompt   = ChatWindow.FormatWhisperPrompt (SystemData.UserInput.ReplyToPlayerName[replyIndex])
        sendTell        = true
    end
    
    if (sendTell == true) then
        ChatWindow.SwitchToChatChannel (SystemData.ChatLogFilters.TELL_SEND, whisperPrompt, iexistingText)        
    end

end


function ChatWindow.FormatWhisperPrompt (iwhisperTarget)

    -- Set the global whisperTarget
    whisperTarget = iwhisperTarget

    -- Then format the tell prompt
    local replacement = {}
    replacement[1] = iwhisperTarget
    replacement[2] = nil
                            
    return GetFormatStringFromTable ("ChatStrings", StringTables.Chat.CHAT_CHANNEL_REPLACE_TELL, replacement)

end

function ChatWindow.SwitchToChatChannel (ichannelIdx, ichannelPrompt, iexistingText)

    if (ichannelIdx == SystemData.ChatLogFilters.TELL_SEND and whisperTarget == nil) then
        return
    end
    ChatWindow.UpdateCurrentChannel (ichannelIdx)

    local channelColorIdx = ichannelIdx

    local channelColor = ChatSettings.ChannelColors[ channelColorIdx ]
    
    TextEditBoxSetTextColor ("ChatWindowContainerTextInput", channelColor.r, channelColor.g, channelColor.b)

    if (iexistingText ~= nil) then
        TextEditBoxSetText("ChatWindowContainerTextInput", iexistingText)
    else
        TextEditBoxSetText("ChatWindowContainerTextInput", L"")  
    end
    
    WindowAssignFocus( "ChatWindowContainerTextInput", true )

    LabelSetTextColor ("ChatWindowContainerChannelLabel", channelColor.r, channelColor.g, channelColor.b)
    LabelSetText ("ChatWindowContainerChannelLabel", ichannelPrompt)
end

-- //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
--
--                                      Chat Tab Menus
--

function ChatWindow.OnOpenChatMenu()
    lastChatWindowName = SystemData.MouseOverWindow.name
    ChatWindow.activeWindow = WindowGetId(WindowGetParent(lastChatWindowName))
    
    ChatWindow.OnSelectTab()
    
	local id = WindowGetId( ChatWindow.GetCurrentTabName() )
    EA_Window_ContextMenu.Hide(EA_Window_ContextMenu.CONTEXT_MENU_2)
    EA_Window_ContextMenu.Hide(EA_Window_ContextMenu.CONTEXT_MENU_3)
    EA_Window_ContextMenu.CreateContextMenu("", EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.Font), ChatWindow.OnViewChatFonts, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.ChatFilters), ChatWindow.OnViewChatFilters, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    ButtonSetPressedFlag("ChatWindowContextShowTimestampButton", ChatWindow.Windows[id].showTimestamp)
    EA_Window_ContextMenu.AddUserDefinedMenuItem("ChatWindowContextShowTimestamp", EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.NewTab), ChatWindow.OnNewWindow, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.RenameTab), ChatWindow.OnRenameTab, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.AddMenuItem(GetStringFromTid(ChatWindow.TID.RemoveTab), ChatWindow.OnRemoveTab, not CanRemoveTab( ChatWindow.activeWindow, id ), true, EA_Window_ContextMenu.CONTEXT_MENU_1)
    EA_Window_ContextMenu.Finalize(EA_Window_ContextMenu.CONTEXT_MENU_1)
    ChatWindow.dockableWindowData[ChatWindow.activeWindow].isContextMenuShowing = true
    -- If this window has been faded out, or in the midst. Fade it back in.
    if (ChatWindow.dockableWindowData[ChatWindow.activeWindow].isWindowAlphaMin == true and
        ChatWindow.dockableWindowData[ChatWindow.activeWindow].idxRootWindow ~= 0 )
    then
        ChatWindow.PerformFadeIn(ChatWindow.dockableWindowData[ChatWindow.activeWindow].idxRootWindow)
    end
end

function ChatWindow.ShowMenu( tabName )

    WindowClearAnchors( "ChatMenuWindow" )
    WindowAddAnchor( "ChatMenuWindow", "topleft", tabName, "bottomleft", 5, -1 )    
    WindowSetShowing("ChatMenuWindow", true)
        
    WindowSetAlpha( "ChatMenuWindow", 0.85 )
    WindowSetAlpha( "ChatMenuWindowSelection", 0.25 )

    ButtonSetDisabledFlag( "ChatMenuWindowRemoveTabButton", not CanRemoveTab( ChatWindow.activeWindow, id ) )
end


function ChatWindow.OnLButtonDownProcessed()
    -- make sure not to close if we click inside a menu
    winName = "ChatChannelMenu"
    if string.sub(SystemData.MouseOverWindow.name,1,string.len(winName))==winName then
        return
    end

    if ( SystemData.InputProcessed.LButtonDown == false ) then   
        ChatWindow.HideMenu()
    end
end

function ChatWindow.OnRButtonDownProcessed()
    ChatWindow.HideMenu()
end

function ChatWindow.HideMenu()
    if( WindowGetShowing( "ChatChannelSelectionWindow" ) == true ) then
        WindowSetShowing("ChatChannelSelectionWindow", false)
    end

    for idxW, wnd in pairs(ChatWindow.Windows) do
        ChatWindow.dockableWindowData[idxW].isContextMenuShowing = false
        if (GetMouseOverChatWindow() ~= nil)
        then
            -- If the user is still over the chatWindow, don't set the fade just yet
            ChatWindow.dockableWindowData[idxW].fadeOutTimer = 0
        elseif (ChatWindow.dockableWindowData[idxW].fadeOutTimer == 0)
        then
            -- If the fadeOutTimer is not currently set, set it now so that the tabs will fade properly
            ChatWindow.dockableWindowData[idxW].fadeOutTimer = ChatWindow.FADE_OUT_DELAY
    end
    end
end

function ChatWindow.GetCurrentTabName()
    return WindowGetParent(lastChatWindowName)
end

function ChatWindow.GetCurrentTabID()
    return WindowGetId(WindowGetParent(lastChatWindowName))
end

function ChatWindow.GetMenuTab()
--    ChatWindow.Windows[WindowGetId(WindowGetParent(lastChatWindowName))]
    
    local wnd = ChatWindow.Windows[WindowGetId(WindowGetParent(lastChatWindowName))]
    if (wnd~=nil) then
        return wnd.Tabs[1]
    end
end

function ChatWindow.OnViewChatOptions()
	ChatWindow.activeWindow = 1
    WindowSetShowing( "ChatOptionsWindow", true)
    ChatWindow.HideMenu()
end

function ChatWindow.OnViewChatFilters()
    WindowSetShowing( "ChatFiltersWindow", true)
    ChatWindow.HideMenu()
end 

function ChatWindow.OnViewChatFonts()
    CreateWindowFromTemplate( "ChatFontWindow", "ChatFontWindowTemplate", "Root" )
    ChatWindow.HideMenu()
end 

-- //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
--
--                                      Tab Options
--

function ChatWindow.OnRenameTab()
    ChatWindow.HideMenu()
    WindowSetShowing( "ChatWindowRenameWindow", true )
    
    tabName = DockableWindowGetTabString(ChatWindow.GetCurrentTabName())
    TextEditBoxSetText( "ChatWindowRenameWindowText", tabName )
    WindowSetTintColor( "ChatWindowRenameWindowText", 255,255,255 )
end

function ChatWindow.OnRename()

    local newName = TextEditBoxGetText( "ChatWindowRenameWindowText" )
    DockableWindowSetTabString(ChatWindow.GetCurrentTabName(), newName)
    WindowSetShowing( "ChatWindowRenameWindow", false )

	local id = WindowGetId( ChatWindow.GetCurrentTabName() )
	ChatWindow.Windows[id].Tabs[1].labelName = newName

	bDirty = true
end

function ChatWindow.OnCancelRename()
    WindowSetShowing( "ChatWindowRenameWindow", false )
end

function ChatWindow.OnRenameTextChanged( text )
    WindowSetTintColor( "ChatWindowRenameWindowText", 255,255,255 )
end

function ChatWindow.AddSizeToFontSizeMenu( fontSize, fontName )
    ChatWindow.NUM_FONT_SIZE_BUTTONS = ChatWindow.NUM_FONT_SIZE_BUTTONS + 1
    local num = ChatWindow.NUM_FONT_SIZE_BUTTONS

    ChatWindow.FontSizeButtons[ num ] = {}
    ChatWindow.FontSizeButtons[ num ].fontSize = fontSize
    ChatWindow.FontSizeButtons[ num ].fontName = fontName

    --DEBUG(L"Adding Font Size: "..fontSize)

        -- status 
    local buttonName = "ChatMenuFontSizeWindow"..fontSize.."StatusButton"
    CreateWindowFromTemplate( buttonName, "ChatMenuFontSizeStatusButton", "ChatMenuFontSizeWindow" )
    ChatWindow.FontSizeButtons[ num ].statusButton = buttonName
    ButtonSetText( buttonName, L"*" )
    WindowSetId( buttonName, num )
    WindowClearAnchors( buttonName )
    if num > 1 then
        WindowAddAnchor( buttonName, "bottomleft", ChatWindow.FontSizeButtons[ num-1 ].statusButton , "topleft", 0, 5 )
    else
        WindowAddAnchor( buttonName, "topleft", "ChatMenuFontSizeWindow" , "topleft", 10, 10 )
    end

      -- name
    local buttonName = "ChatMenuFontSizeWindow"..fontSize.."NameButton"
    CreateWindowFromTemplate( buttonName, "ChatMenuFontSizeNameButton", "ChatMenuFontSizeWindow" )
    ChatWindow.FontSizeButtons[ num ].nameButton = buttonName
    ButtonSetText( buttonName, L""..fontSize )
    WindowSetId( buttonName, num )
    WindowClearAnchors( buttonName )
    WindowAddAnchor( buttonName, "topleft", ChatWindow.FontSizeButtons[ num ].statusButton , "topleft", 22, 0 )
end

function ChatWindow.AddFontToFontMenu( fontName, fontDefinition )
    ChatWindow.NUM_FONT_SIZE_BUTTONS = ChatWindow.NUM_FONT_SIZE_BUTTONS + 1
    local num = ChatWindow.NUM_FONT_SIZE_BUTTONS

    ChatWindow.FontButtons[ num ] = {}
    ChatWindow.FontButtons[ num ].fontName = fontName
    ChatWindow.FontButtons[ num ].fontDefinition = fontDefinition

    --DEBUG(L"Adding Font Size: "..StringToWString(fontName))

        -- status 
    local buttonName = "ChatMenuFontWindow"..fontDefinition.."StatusButton"
    CreateWindowFromTemplate( buttonName, "ChatMenuFontStatusButton", "ChatMenuFontWindow" )
    ChatWindow.FontButtons[ num ].statusButton = buttonName
    ButtonSetText( buttonName, L"*" )
    WindowSetId( buttonName, num )
    WindowClearAnchors( buttonName )
    if num > 1 then
        WindowAddAnchor( buttonName, "bottomleft", ChatWindow.FontButtons[ num-1 ].statusButton , "topleft", 0, 5 )
    else
        WindowAddAnchor( buttonName, "topleft", "ChatMenuFontWindow" , "topleft", 10, 10 )
    end

    --DEBUG(L"Naming button to: "..StringToWString(fontName))
      -- name
    local buttonName = "ChatMenuFontWindow"..fontName.."NameButton"
    CreateWindowFromTemplate( buttonName, "ChatMenuFontNameButton", "ChatMenuFontWindow" )
    ChatWindow.FontButtons[ num ].nameButton = buttonName
    ButtonSetText( buttonName, StringToWString(fontName) )
    WindowSetId( buttonName, num )
    WindowClearAnchors( buttonName )
    WindowAddAnchor( buttonName, "topleft", ChatWindow.FontButtons[ num ].statusButton , "topleft", 22, 0 )
end

function ChatWindow.OnSizeButton()
    local sizeIdx = WindowGetId(SystemData.ActiveWindow.name)
    local tab = ChatWindow.GetMenuTab()
    local font = ChatWindow.FontButtons[ sizeIdx ].fontDefinition
    LogDisplaySetFont( tab.tabWindow, font )
    ChatWindow.OnViewFontMenu()
    --DEBUG(L"TODO - refresh the chat log wrapping")
	bDirty = true
end

function ChatWindow.OnSelectFontNameButton()
    local sizeIdx = WindowGetId(SystemData.ActiveWindow.name)
    local tab = ChatWindow.GetMenuTab()
    local font = ChatWindow.FontButtons[ sizeIdx ].fontDefinition
    LogDisplaySetFont( tab.tabWindow, font )
    ChatWindow.OnViewFontMenu()
	bDirty = true
end


function ChatWindow.OnNewWindow( defaultLogOrNil )
    ChatWindow.HideMenu()
    local wndNum = #ChatWindow.Windows + 1

    --Debug.Print("Adding a new window: "..tostring(wndNum))

    ChatWindow.Windows[wndNum] = {}
    
    ChatWindow.dockableWindowData[wndNum] = {}
    ChatWindow.dockableWindowData[wndNum].fadeInTimer = 0
    ChatWindow.dockableWindowData[wndNum].fadeOutTimer = 0
    ChatWindow.dockableWindowData[wndNum].idxRootWindow = 0
    ChatWindow.dockableWindowData[wndNum].isContextMenuShowing = false
    ChatWindow.dockableWindowData[wndNum].isWindowAlphaMin = true
    ChatWindow.dockableWindowData[wndNum].isUndocking = false
    
    local wnd = ChatWindow.Windows[wndNum]
    wnd.Tabs = {}
    wnd.activeTab = 1
    
    local rootWindowName = lastChatWindowName
    if (rootWindowName ~= nil) then
        rootWindowName = WindowGetParent(rootWindowName)
        local rootWindowIndex = WindowGetId(lastChatWindowName)
        if (rootWindowIndex <= 0 or rootWindowIndex > #ChatWindow.Windows or rootWindowIndex == nil)
        then
            wnd.windowMinAlpha = WINDOW_MIN_ALPHA
        else
            wnd.windowMinAlpha = ChatWindow.Windows[rootWindowIndex].windowMinAlpha
        end
        if (rootWindowIndex <= 0 or rootWindowIndex > #ChatWindow.Windows or rootWindowIndex == nil)
        then
            wnd.windowMaxAlpha = DEFAULT_WINDOW_MAX_ALPHA
        else
            wnd.windowMaxAlpha = ChatWindow.Windows[rootWindowIndex].windowMaxAlpha
        end
    else
        wnd.windowMinAlpha = WINDOW_MIN_ALPHA
        wnd.windowMaxAlpha = DEFAULT_WINDOW_MAX_ALPHA
    end
    wnd.wndName = ChatWindow.AddDockableWindow(rootWindowName)
	--CreateWindowFromTemplate( wnd.wndName ,"ChatWindowTemplate","Root")
    WindowSetId( wnd.wndName, wndNum )

    -- the first tab is built-in by XML, must have name = parent+componentName
    local tabName = wnd.wndName.."ChatTab"
    local logDisplayName = wnd.wndName.."ChatLogDisplay"
    local labelName = StringToWString(wnd.wndName)

    --wnd.optionsButton = wnd.wndName.."OptionsButton"
    wnd.resizeButton = wnd.wndName.."ResizeButton"
    wnd.background = wnd.wndName.."Background"
    wnd.showTimestamp = false

    ChatWindow.SetupNewTab( wndNum, defaultLogOrNil, 1, labelName, tabName, logDisplayName )

    for idxT, tab in pairs(wnd.Tabs) do
        WindowSetAlpha( tab.tabButton, WINDOW_MIN_ALPHA )
        WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
    end
    --WindowSetAlpha( wnd.optionsButton, WINDOW_MIN_ALPHA )
    --WindowSetAlpha( wnd.wndName.."Foreground", WINDOW_FULL_ALPHA )
    --WindowSetShowing( wnd.wndName.."Foreground", true )
    WindowSetAlpha( wnd.resizeButton, wnd.windowMaxAlpha )
    WindowSetAlpha( wnd.background, wnd.windowMaxAlpha )
    WindowSetAlpha( wnd.wndName.."Tab", wnd.windowMaxAlpha )
    
    if (skipSave == false) then
		bDirty = true
    end

end


function ChatWindow.GetAvailableWindowName()
    for num = 2, 10000 do
        local wndName = "ChatWindow"..num
        if not DoesWindowExist( wndName ) then
            return wndName
        end
    end
end 


function ChatWindow.GetAvailableTabLogNames()
    for num = 2, 10000 do
        local tabName = "ChatWindowTab"..num
        local logName = "ChatWindowLogDisplay"..num
        if not ( DoesWindowExist( tabName ) or DoesWindowExist( logName ) ) then
            return tabName, logName
        end
    end
end 

function ChatWindow.CreateNewTab( wndNum, givenName )
    local wnd = ChatWindow.Windows[wndNum]
    if wnd == nil then return end

    local tabNum = wnd.numTabs + 1

    local labelName = L""
    if givenName ~= nil then
        labelName = StringToWString(givenName)
    end
    
    local tabName, logDisplayName = ChatWindow.GetAvailableTabLogNames()
    CreateWindowFromTemplate( tabName, "ChatTabButton", wnd.wndName)
    CreateWindowFromTemplate( logDisplayName, "ChatLogDisplay", wnd.wndName )

    return { tabNum, labelName, tabName, logDisplayName }
end

function ChatWindow.SetupNewTab( wndNum, defaultLog, tabNum, labelName, tabName, logDisplayName  )
    WindowSetShowing(tabName, false)
    local wnd = ChatWindow.Windows[wndNum]
    if wnd == nil then return end

    --Debug.Print("ChatWindow.SetupNewTab: "..tostring(wndNum)..", "..tostring(defaultLog)..", "..tostring(tabNum))
    -- clone a button and log display
    WindowSetId( tabName, tabNum ) 
    --if tabNum ~= 1 then    
    --    WindowClearAnchors( tabName )
    --    WindowAddAnchor( tabName, "topright", wnd.Tabs[ tabNum-1 ].tabButton , "topleft", -2, 0 )
    --end
    -- setup our new tab
    wnd.Tabs[ tabNum ] = {}
    wnd.Tabs[ tabNum ].labelName = labelName
    wnd.Tabs[ tabNum ].tabButton = tabName
    wnd.Tabs[ tabNum ].tabWindow = logDisplayName
    wnd.Tabs[ tabNum ].defaultLog = defaultLog
    wnd.numTabs = tabNum

    ChatWindow.dockableWindowData[wndNum] = {}
    ChatWindow.dockableWindowData[wndNum].fadeInTimer              = 0
    ChatWindow.dockableWindowData[wndNum].fadeOutTimer             = 0
    ChatWindow.dockableWindowData[wndNum].idxRootWindow            = 0
    ChatWindow.dockableWindowData[wndNum].isContextMenuShowing     = false
    ChatWindow.dockableWindowData[wndNum].isWindowAlphaMin         = true
    
    -- Add the Chat and Combat Log to the display
    LogDisplayAddLog( logDisplayName, "Chat", true )
     
    for filterId, msgTypeData in pairs( ChatSettings.Channels ) 
    do
        if( wndNum == 2 ) then
			LogDisplaySetFilterState( logDisplayName, msgTypeData.logName, msgTypeData.id, (msgTypeData.isOnAlways or msgTypeData.isOnJournal) )
        else
			LogDisplaySetFilterState( logDisplayName, msgTypeData.logName, msgTypeData.id, (msgTypeData.isOnAlways or msgTypeData.isOnChat) )
		end

        local color = ChatSettings.ChannelColors[ filterId ]
        LogDisplaySetFilterColor( logDisplayName, msgTypeData.logName, msgTypeData.id, color.r, color.g, color.b )
    end

    -- Set the fade time of the text
    LogDisplaySetTextFadeTime(wnd.Tabs[ tabNum ].tabWindow, 10)
    
     -- Add the System Log to the first tab
    --if tabNum == 1 
        --and wndNum == 1 then
        --LogDisplayAddLog( logDisplayName, "System", true)
        --LogDisplaySetFilterColor( logDisplayName, "System", SystemData.SystemLogFilters.GENERAL, 255, 255, 255);   
        --LogDisplaySetFilterColor( logDisplayName, "System", SystemData.SystemLogFilters.ERROR, 255, 100, 0);  
    --end
    
    WindowSetAlpha( tabName, WINDOW_MIN_ALPHA )
    WindowSetFontAlpha( tabName, WINDOW_MIN_ALPHA )
    WindowSetAlpha( logDisplayName, WINDOW_MIN_ALPHA )
    
    ButtonSetText( tabName, labelName )
    ButtonSetStayDownFlag( tabName, true )
   
    ChatWindow.OnUpdate(0.001) 
    ChatWindow.ShowTab( wndNum, tabNum )
end

function ChatWindow.ToggleTimestamp()
    bDirty = true
    local wndNum = ChatWindow.GetCurrentTabID()
    local tab = ChatWindow.Windows[wndNum].Tabs[1]
    -- Toggle the timestamp
    if (ChatWindow.Windows[wndNum].showTimestamp == true)
    then
        ChatWindow.Windows[wndNum].showTimestamp = false
    else
        ChatWindow.Windows[wndNum].showTimestamp = true
    end
    ButtonSetPressedFlag("ChatWindowContextShowTimestampButton", ChatWindow.Windows[wndNum].showTimestamp)
    LogDisplaySetShowTimestamp( tab.tabWindow, ChatWindow.Windows[wndNum].showTimestamp)
end

function ChatWindow.ToggleAutoHide()
    bDirty = true
    -- Toggle the auto-hide
    if (ChatWindow.autohide == true)
    then
        ChatWindow.autohide = false
        for idxW, wnd in pairs(ChatWindow.Windows) do
			if (ChatWindow.dockableWindowData[idxW].isWindowAlphaMin == true) then
				if(ChatWindow.windowLocked == false) then
					WindowSetAlpha ( wnd.resizeButton, wnd.windowMaxAlpha)
				end
				WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, wnd.windowMinAlpha, wnd.windowMaxAlpha, 2.0, false, 0, 0 )
				for idxT, tab in pairs(wnd.Tabs) do
					WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, wnd.windowMinAlpha, wnd.windowMaxAlpha, 2.0, false, 0, 0 )
				end
				ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = false
			end
        end
    else
        ChatWindow.autohide = true
        ChatWindow.PerformFadeOut()
    end
    ButtonSetPressedFlag("ChatWindowContextAutoHideButton", ChatWindow.autohide)
end

function ChatWindow.SetFontToSelection()
    local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
    local wndNum = ChatWindow.GetCurrentTabID()
    local tab = ChatWindow.Windows[wndNum].Tabs[1]
    for idx=1, #ChatSettings.Fonts do
        WindowSetShowing("ChatWindowContextFontMenuItem"..idx.."Check", false)
    end
    WindowSetShowing(SystemData.ActiveWindow.name.."Check", true)
    LogDisplaySetFont(tab.tabWindow, ChatSettings.Fonts[fontIndex].fontName)
    bDirty = true
    
end

function ChatWindow.OnRemoveTab()
    local wndNum = ChatWindow.GetCurrentTabID()
    local tabNum = 1
    ChatWindow.RemoveTab( wndNum, tabNum )
    ChatWindow.ClearChatSaveSlot(wndNum)
end

function ChatWindow.RemoveTab( wndNum, tabNum )
    local wnd = ChatWindow.Windows[wndNum]
    if wnd == nil then return end

    -- don't allow the removal of the base tab
    if not CanRemoveTab( wndNum, tabNum ) then
        return
    end

--    -- DEBUG(L"Removing tab: "..tabNum..L" from wnd: "..wndNum)

    if (wnd.wndName ~= DockableWindowGetRootName(wnd.wndName)) then
        lastChatWindowName = DockableWindowGetRootName(wnd.wndName)
        DockableWindowSetTopWindow(lastChatWindowName, lastChatWindowName)
        for idxT, tab in pairs(wnd.Tabs) do
            WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
        end
        DockableWindowUnDock(lastChatWindowName, wnd.wndName)
    end
    -- hide the menu only if we're actually doing something
    ChatWindow.HideMenu()

    -- if this is the last tab of the non-base window, kill the window
    if ( wndNum ~= 1
        and tabNum == 1 ) then
        ChatWindow.RemoveWindow( wndNum )
        return
    end

    ChatWindow.ShowTab( wndNum, 1 ) 
   
   -- Destroy this tab
    DestroyWindow( wnd.Tabs[tabNum].tabButton )
    DestroyWindow( wnd.Tabs[tabNum].tabWindow ) 

    -- Shift all tabs after this one
    for index = tabNum, wnd.numTabs-1 do
       wnd.Tabs[index] = wnd.Tabs[index+1]
       WindowSetId( wnd.Tabs[index].tabButton, index )
    end 
   
    wnd.Tabs[ wnd.numTabs ] = nil
    wnd.numTabs = wnd.numTabs - 1
   
    if wnd.Tabs[tabNum] ~= nil then
        WindowClearAnchors( wnd.Tabs[tabNum].tabButton )
        WindowAddAnchor( wnd.Tabs[tabNum].tabButton, "topright", wnd.Tabs[ tabNum-1 ].tabButton , "topleft", -2, 0 )    
    end
    ChatWindow.ResetRootDockableWindowDataVariables()
    ChatWindow.PerformFadeIn( WindowGetId(lastChatWindowName) )
end


function ChatWindow.RemoveWindow( wndNum )
    --Debug.Print(L"Removing Chat Window #"..wndNum)
    
    local wnd = ChatWindow.Windows[wndNum]
    if wnd == nil then return end

    local childName = DockableWindowGetChildName( wnd.wndName, 1 )
    local x,y
    if childName ~= "" then
		x,y = WindowGetOffsetFromParent( childName )
	end
    DestroyWindow( wnd.wndName )
    
    if childName ~= "" then
        WindowSetOffsetFromParent( childName, x, y )
        DockableWindowSetOffsetOnRootDelete( childName, x, y )
    end

    -- Shift all windows after this one
    local numWnds = #ChatWindow.Windows
    for index = wndNum, numWnds-1 do
        ChatWindow.Windows[index] = ChatWindow.Windows[index+1]
        WindowSetId( ChatWindow.Windows[index].wndName, index )
    end

    ChatWindow.Windows[ numWnds ] = nil
end

function ChatWindow.AddDockableWindow(rootWindowName)
	local childWindowName = ChatWindow.GetAvailableWindowName()
    CreateWindowFromTemplate( childWindowName ,"ChatWindowTemplate","Root")
    DockableWindowSetTabString(childWindowName, StringToWString(childWindowName))
    DockableWindowSetTabOffset( childWindowName, 0 )

    if rootWindowName ~= nil then 
        DockableWindowDock( rootWindowName, childWindowName )
        DockableWindowSetTopWindow(rootWindowName, childWindowName)
        local numWnds = #ChatWindow.Windows
        for index = 1, numWnds do
            for idxT, tab in pairs(ChatWindow.Windows[index].Tabs) do
                WindowSetAlpha( tab.tabWindow, WINDOW_FULL_ALPHA )
            end
        end
    end
    return childWindowName
end

function ChatWindow.InitRootChatTab()
    WindowSetShowing("ChatWindowChatTab", false)
    DockableWindowSetTabString("ChatWindow", GetStringFromTid(ChatWindow.TID.System))
    DockableWindowSetTabOffset( "ChatWindow", 0 )
end

function ChatWindow.LoadChatWindowSettings( windowName, savedWindowName, saveWnd )
	-- Window Size
    WindowSetDimensions( windowName, saveWnd.sizeX, saveWnd.sizeY )

    -- Window Position
    local screenX, screenY = GetScreenResolution()
    local scale = WindowGetScale( windowName )
    local offsetX = saveWnd.posX * screenX / scale
    local offsetY = saveWnd.posY * screenY / scale
        
    WindowClearAnchors( windowName )
    WindowAddAnchor( windowName, "topleft", "Root", "topleft", offsetX, offsetY )

    -- Movable
    DockableWindowSetMovable( windowName, saveWnd.movable)
    
    -- Alpha
    WindowSetAlpha( windowName, WINDOW_FULL_ALPHA)

	local wszMovable
	if saveWnd.movable then
		wszMovable = L"true"
	else
		wszMovable = L"false"
	end
	--DEBUG(L"LOADING...")
	--DEBUG(StringToWString(windowName)..L": offset:("..saveWnd.posX..L","..saveWnd.posY..L") size:("..saveWnd.sizeX..L","..saveWnd.sizeY..L") movable: "..wszMovable..L" alpha: "..saveWnd.alpha)
    return true

end

function ChatWindow.IsMainWindowGroup(wndName)
    if (DockableWindowGetRootName(wndName) == ChatWindow.Windows[1].wndName) 
        or (DockableWindowIsChildOf(DockableWindowGetRootName(wndName), ChatWindow.Windows[1].wndName)) then
        return true
    end
    
    return false
end

function ChatWindow.SaveChatWindowToSlot(iIndex)
end

function ChatWindow.LoadChatWindowFromSlot(iIndex)
end

function ChatWindow.ClearChatSaveSlot(iIndex)
	ChatWindow.Settings.Chat.Windows[iIndex] = nil
	bDirty = true
end

function ChatWindow.OnDock( parentWindowName, childWindowName )
    --Debug.Print("ChatWindow.OnDock: "..tostring(parentWindowName).." .. "..tostring(childWindowName))
	bDirty = true
	ChatWindow.ResetRootDockableWindowDataVariables()
	local rootName = DockableWindowGetRootName(childWindowName)
	local rootId = WindowGetId(rootName)
	local childId = WindowGetId(childWindowName)
	
	-- Set the Opacity of the docked window to the same as the Root
	if (childId <= 0 or childId > #ChatWindow.Windows)
	then
	    ChatWindow.PerformFadeIn(rootId)
	    return
	else
	    ChatWindow.Windows[childId].windowMinAlpha = ChatWindow.Windows[rootId].windowMinAlpha
	    ChatWindow.Windows[childId].windowMaxAlpha = ChatWindow.Windows[rootId].windowMaxAlpha
	    
	    if(ChatWindow.Windows[childId].wndName ~= nil) then
            -- Need to set this docked window to the correct Alpha, because we don't Fade
            WindowStopAlphaAnimation(ChatWindow.Windows[childId].wndName.."Tab")
            WindowStopAlphaAnimation( ChatWindow.Windows[childId].background )
            WindowSetAlpha(ChatWindow.Windows[childId].background, ChatWindow.Windows[childId].windowMaxAlpha)
            WindowSetAlpha(ChatWindow.Windows[childId].wndName.."Tab", ChatWindow.Windows[childId].windowMaxAlpha)
            WindowSetFontAlpha(ChatWindow.Windows[childId].wndName.."Tab", ChatWindow.Windows[childId].windowMaxAlpha)
        end
	end
end

function ChatWindow.OnUnDock( parentWindowName, childWindowName )
    bUnDocking = true
    UnDockingWindowName = SystemData.ActiveWindow.name
	bDirty = true
	local windowIdText = L""..WindowGetId( childWindowName )

	local preRootId = WindowGetId( DockableWindowGetRootName(SystemData.ActiveWindow.name) )
	ChatWindow.ResetRootDockableWindowDataVariables()
	local postRootId = WindowGetId( DockableWindowGetRootName(SystemData.ActiveWindow.name) )
	ChatWindow.PerformFadeIn(preRootId)
	ChatWindow.dockableWindowData[preRootId].fadeOutTimer = ChatWindow.FADE_OUT_DELAY
	ChatWindow.dockableWindowData[preRootId].isUndocking = true
	ChatWindow.PerformFadeIn(postRootId)
end

function ChatWindow.ResetRootDockableWindowDataVariables()
	-- If any of our indexes have been set, reset them because they have been changed
    local rootName
    for idxW, wnd in pairs(ChatWindow.Windows) do
        if (wnd.wndName == nil)
        then
            -- default the tab's root window to Chat Tab, this will change when the user undocks the window.
            ChatWindow.dockableWindowData[idxW].idxRootWindow = 1
        else
            rootName = DockableWindowGetRootName(wnd.wndName)
            ChatWindow.dockableWindowData[idxW].idxRootWindow = WindowGetId(rootName)
        end
        
    end
end

function ChatWindow.OnSizeUpdated(width, height)
	if (not bLoading) then
		bDirty = true
	end
end

function ChatWindow.OnSetMoving( bMoving )
	-- we only care if we have stopped moving
	if (not bLoading) and (not bMoving) then
		bDirty = true
		if (WindowGetShowing("ChatWindowContainer") == true and bUnDocking == false)
		then
		    WindowAssignFocus( "ChatWindowContainerTextInput", true )
		end
		if (bUnDocking == true and UnDockingWindowName == SystemData.ActiveWindow.name)
		then
		    bUnDocking = false
		end
	end
end

function ChatWindow.OnWindowOptionsSetAlpha()
    --Debug.Print("ChatWindow.OnWindowOptionsSetAlpha")
    -- Open the Alpha Slider    
    local minAlpha = ChatWindow.Windows[1].windowMinAlpha
    local maxAlpha = ChatWindow.Windows[1].windowMaxAlpha
    SliderBarSetCurrentPosition("ChatWindowSetOpacityWindowSliderMinAlpha", minAlpha )
    SliderBarSetCurrentPosition("ChatWindowSetOpacityWindowSliderMaxAlpha", maxAlpha )
    
    -- Anchor the OpacityWindow in the middle of the active window.
    WindowClearAnchors( "ChatWindowSetOpacityWindow" )
    WindowAddAnchor( "ChatWindowSetOpacityWindow", "left", "EA_Window_ContextMenu1", "left", 0, 0 )

    WindowSetShowing( "ChatWindowSetOpacityWindow", true )
end

function ChatWindow.OnSlideWindowOptionsMinAlpha( slidePos )
    --Debug.Print("ChatWindow.OnSlideWindowOptionsMinAlpha")
    local alpha = slidePos
    
    if (alpha < 0) then
        alpha = 0
    end
    -- this if statement is a stop gap to prevent this call from happening with a bad window
    -- the bad call when using ctrl+alt+del should be tracked down
    for idxW, wnd in pairs(ChatWindow.Windows) do
		if( ChatWindow.autohide == true ) then
			WindowStopAlphaAnimation( wnd.wndName.."Tab" )
			WindowSetAlpha( wnd.wndName.."Tab", alpha )
			WindowSetFontAlpha( wnd.wndName.."Tab", alpha )
			
			if( ChatWindow.windowLocked == false ) then
				WindowSetAlpha( wnd.resizeButton, alpha )
			end
			
			WindowStopAlphaAnimation( wnd.background )
			WindowSetAlpha( wnd.background, alpha )
		end
    end
end

function ChatWindow.OnSlideWindowOptionsMaxAlpha( slidePos )
    --Debug.Print("ChatWindow.OnSlideWindowOptionsMaxAlpha")
    local alpha = slidePos
    
    -- Requirements call for 1%-100% range, not 0% to 100%.
    if (alpha < 0.01) then
        alpha = 0.01
    end
    -- this if statement is a stop gap to prevent this call from happening with a bad window
    -- the bad call when using ctrl+alt+del should be tracked down
    for idxW, wnd in pairs(ChatWindow.Windows) do
		if( ChatWindow.autohide == false ) then
			WindowStopAlphaAnimation( wnd.wndName.."Tab" )
			WindowSetAlpha( wnd.wndName.."Tab", alpha )
			WindowSetFontAlpha( wnd.wndName.."Tab", alpha )
			
			if( ChatWindow.windowLocked == false ) then
				WindowSetAlpha( wnd.resizeButton, alpha )
			end
			
			WindowStopAlphaAnimation( wnd.background )
			WindowSetAlpha( wnd.background, alpha )
		end
    end
end

function ChatWindow.CloseSetOpacityWindow()
    local newMinAlpha = SliderBarGetCurrentPosition("ChatWindowSetOpacityWindowSliderMinAlpha")
    local newMaxAlpha = SliderBarGetCurrentPosition("ChatWindowSetOpacityWindowSliderMaxAlpha")
    if (newMinAlpha < 0) then
        newMinAlpha = 0
    end
    if (newMaxAlpha < 0.01) then
        newMaxAlpha = 0.01
    end
    
    for idxW, wnd in pairs(ChatWindow.Windows) do
		wnd.windowMinAlpha = newMinAlpha
        wnd.windowMaxAlpha = newMaxAlpha
    end
    
    WindowSetShowing( "ChatWindowSetOpacityWindow", false )
    ChatWindow.HideMenu()
end

function ChatWindow.LockWindow(isLocked)
	ChatWindow.windowLocked = isLocked

    for idxW, wnd in pairs(ChatWindow.Windows) do
        WindowSetMovable(wnd.wndName, not isLocked)
    end

    if( isLocked ) then
        for idxW, wnd in pairs(ChatWindow.Windows) do
			WindowSetAlpha ( wnd.resizeButton, WINDOW_MIN_ALPHA)
            if (ChatWindow.autohide == true and ChatWindow.dockableWindowData[idxW].isWindowAlphaMin == false) then
				WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
				for idxT, tab in pairs(wnd.Tabs) do
	                WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, wnd.windowMaxAlpha, wnd.windowMinAlpha, 2.0, false, 0, 0 )
				end
				ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = true
			end
        end
    else
		for idxW, wnd in pairs(ChatWindow.Windows) do
			WindowSetAlpha ( wnd.resizeButton, wnd.windowMaxAlpha)
			if (ChatWindow.dockableWindowData[idxW].isWindowAlphaMin == true) then
				WindowStartAlphaAnimation ( wnd.background, Window.AnimationType.SINGLE_NO_RESET, wnd.windowMinAlpha, wnd.windowMaxAlpha, 2.0, false, 0, 0 )
				for idxT, tab in pairs(wnd.Tabs) do
					WindowStartAlphaAnimation ( wnd.wndName.."Tab", Window.AnimationType.SINGLE_NO_RESET, wnd.windowMinAlpha, wnd.windowMaxAlpha, 2.0, false, 0, 0 )
				end
				ChatWindow.dockableWindowData[idxW].isWindowAlphaMin = false
			end
        end
    end
end

function ChatWindow.OnLockButtonClicked()    
    ChatWindow.LockWindow(not ChatWindow.windowLocked)
    bDirty = true
end

function ChatWindow.OnInputTextButtonMouseOver()
	Tooltips.CreateTextOnlyTooltip("ChatWindowInputTextButton", GetStringFromTid(ChatWindow.TID.ChatButtonTooltip))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )	
end

function ChatWindow.OnGChatRosterUpdate()    
    ComboBoxClearMenuItems("ChatChannelSelectionWindowGChatActiveFriendSelectCombo")
    if(WindowData.GChatCount == 0 or ChatWindow.firstGChatSelect)then
        ComboBoxAddMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo",  L"/Select Friend" )
        WindowData.GChatIndex = 1;
        ComboBoxSetSelectedMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo",  WindowData.GChatIndex)        
    end
    for i = 1, WindowData.GChatCount do
       ComboBoxAddMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo",  towstring(WindowData.GChatNameList[i]))        
    end
    if((WindowData.GChatIndex > 0) and (WindowData.GChatIndex <= WindowData.GChatCount))then
        ComboBoxSetSelectedMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo",  WindowData.GChatIndex)        
    else
        ComboBoxSetSelectedMenuItem( "ChatChannelSelectionWindowGChatActiveFriendSelectCombo", 1 ) --SystemData.ChatLogFilters.GLOBAL_CHAT
        WindowData.GChatIndex = 1   
    end     
end


