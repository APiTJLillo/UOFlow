----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

NewChatWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

NewChatWindow.Messages = {}
NewChatWindow.Setting = nil
function NewChatWindow.InitializeSettings()
	if NewChatWindow.Settings == nil then
		NewChatWindow.Settings = {}
	end
	
	local shard = UserData.Settings.Login.lastShardSelected
	if NewChatWindow.Settings[shard] == nil then
		NewChatWindow.Settings[shard] = {}
	end
	
	local user = UserData.Settings.Login.lastUserName

	if NewChatWindow.Settings[shard][user] == nil then
		NewChatWindow.Settings[shard][user] = {}
	end
		
	if NewChatWindow.Settings[shard][user].Messages == nil then
		NewChatWindow.Settings[shard][user].Messages = {}
	end
	
	NewChatWindow.Setting = NewChatWindow.Settings[shard][user]
	for i = table.getn(NewChatWindow.Setting.Messages), 1, -1 do
		table.insert(NewChatWindow.Messages, 1, NewChatWindow.Setting.Messages[i])
	end
	
end

NewChatWindow.Initialized = false 

NewChatWindow.WindowName = "NewChatWindow"
NewChatWindow.WINDOW_WIDTH_MAX = 800
NewChatWindow.WINDOW_HEIGHT_MAX = 800

NewChatWindow.minTotDmg = 200

NewChatWindow.NormalColor = { r=51, g=204, b=255 }
NewChatWindow.ActiveColor = { r=51, g=204, b=51 }
NewChatWindow.HighlightColor = { r=255, g=255, b=0 }

NewChatWindow.maxTabs = 20
NewChatWindow.messagesBuffCap = 500

NewChatWindow.deltaUpd = 0
NewChatWindow.UpdateReq = false

NewChatWindow.firstStart = true

NewChatWindow.blockUpdate = false


NewChatWindow.LastMsg = {}

NewChatWindow.LastVis = {}

NewChatWindow.totalHeight = {}

NewChatWindow.Labels = {}
NewChatWindow.PrevLabels = {}

NewChatWindow.BaseAlpha = 0.7

NewChatWindow.autoHide = false
NewChatWindow.waitTime = 5
NewChatWindow.delta = 0
NewChatWindow.hidden = false
NewChatWindow.showMouseOver = true
NewChatWindow.waithide = false
NewChatWindow.Locked = false
NewChatWindow.TextFade = false
NewChatWindow.TimeStamp = false
NewChatWindow.hideTag = false

NewChatWindow.TabCount = 1
NewChatWindow.TabStatus = {}

NewChatWindow.LastDock = 0

NewChatWindow.ActiveTab = 1

NewChatWindow.ChannelsEnabled = {}

NewChatWindow.DefaultFont = 1
NewChatWindow.ChannelsFonts = {}

NewChatWindow.DefaultFontSize = 16
NewChatWindow.ChannelsFontsSize = {}

NewChatWindow.curChannel =  nil
NewChatWindow.prevChannel = nil

NewChatWindow.MinUpdateRate = 0.3

NewChatWindow.Filter = {}
NewChatWindow.Filter[1] = 	GetStringFromTid(1011051)
NewChatWindow.Filter[2] = 	GetStringFromTid(1154822)
NewChatWindow.Filter[3] = 	GetStringFromTid(1078866)
NewChatWindow.Filter[4] = 	GetStringFromTid(1154823)
NewChatWindow.Filter[5] = 	GetStringFromTid(1153802)
NewChatWindow.Filter[6] = 	GetStringFromTid(1095164)
NewChatWindow.Filter[7] = 	GetStringFromTid(1154824)
NewChatWindow.Filter[8] = 	GetStringFromTid(3000509)
NewChatWindow.Filter[9] = 	GetStringFromTid(1154825)
NewChatWindow.Filter[10] =	GetStringFromTid(1154826)
NewChatWindow.SavedFilter = {}
NewChatWindow.SavedFilter[1] = false
NewChatWindow.SavedFilter[2] = true
NewChatWindow.SavedFilter[3] =  false
NewChatWindow.SavedFilter[4] =  true
NewChatWindow.SavedFilter[5] = true
NewChatWindow.SavedFilter[6] = true
NewChatWindow.SavedFilter[7] = true
NewChatWindow.SavedFilter[8] = false
NewChatWindow.SavedFilter[9] = false
NewChatWindow.SavedFilter[10] = false


NewChatWindow.ShowSpells = false
NewChatWindow.ShowSpellsCasting = false
NewChatWindow.ShowPerfection = false
NewChatWindow.ShowMultiple = true

NewChatWindow.SwitchOrder = {}
NewChatWindow.SwitchID = 1

NewChatWindow.PlayerName = L""

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------
function NewChatWindow.SetVisible()
	WindowSetShowing(NewChatWindow.WindowName, Interface.UseNewChat)
	WindowSetShowing(NewChatWindow.WindowName .. "JournalWindow", Interface.UseNewChat)
	for i = 1, NewChatWindow.maxTabs do
		local templatename = "Bookmark" .. i
		if (DoesWindowNameExist(templatename)) then
			WindowSetShowing(templatename, Interface.UseNewChat)
		end
		if (DoesWindowNameExist("NewChatWindow" .. i)) then
			WindowSetShowing("NewChatWindow" .. i, Interface.UseNewChat)
		end
		if (DoesWindowNameExist("NewChatWindowBookmark" .. i)) then
			WindowSetShowing("NewChatWindowBookmark" .. i, Interface.UseNewChat)
		end
	end
end
function NewChatWindow.HideChannelSelectionMenu()
    WindowAssignFocus( "NewChatChannelSelectionWindow", false )
    WindowSetShowing("NewChatChannelSelectionWindow", false)
end



function NewChatWindow.OnKeyTab()
	NewChatWindow.SwitchID = NewChatWindow.SwitchID + 1
	if NewChatWindow.SwitchID > #NewChatWindow.SwitchOrder then
		NewChatWindow.SwitchID = 1
	end
	NewChatWindow.prevChannel = NewChatWindow.SwitchOrder[NewChatWindow.SwitchID]
	Interface.ChatWindowSwitchChannelWithExistingText (ChatWindowContainerTextInput.Text)
end

function NewChatWindow.SwitchToSelectedChannel()
    local windowId = WindowGetId(SystemData.ActiveWindow.name)
    local chatChannelId
    local label
    if (windowId == 16) then
		chatChannelId = windowId
		label = L"[Self]:"
	else
		chatChannelId = ChatSettings.Channels[windowId].id
		label = ChatSettings.Channels[chatChannelId].labelText
    end
    
    NewChatWindow.SwitchToChatChannel(chatChannelId, label )
    NewChatWindow.UpdateCurrentChannel(chatChannelId)
    -- Show the Text Input Window and Hide the menu
    WindowAssignFocus( "NewChatChannelSelectionWindow", false )
    WindowSetShowing( "ChatWindowContainer", true )
     WindowAssignFocus( "ChatWindowContainerTextInput", true )
    WindowSetShowing("NewChatChannelSelectionWindow", false)
    
end

function NewChatWindow.DragBar()
	this = SystemData.ActiveWindow.name
	local id = WindowGetId(this)
	if (id > 0 and IsMobile(id)) then
		MobilesHealthbar.CreateHealthBar(id)
	else
		WindowSetId(this, 0)
		--WindowSetHandleInput(this, false)
	end
end

function NewChatWindow.UpdateCurrentChannel (icurChannel)
    NewChatWindow.prevChannel = NewChatWindow.curChannel
    NewChatWindow.curChannel  = icurChannel
end

function NewChatWindow.MenuItemMouseLeave()
	this = SystemData.ActiveWindow.name
	local parent = WindowGetParent(this)
	if (not WindowHasFocus("NewChatChannelSelectionWindow") and not WindowHasFocus("NewChatChannelSelectionWindow")) then
		NewChatWindow.HideChannelSelectionMenu()
	end
end



local function IsSlashCommandInChannel( slashCommand, channel )
    return ( slashCommand ~= nil and
             channel ~= nil and
             channel.slashCmds ~= nil and
             channel.slashCmds[slashCommand] == 1 )
end


function NewChatWindow.SwitchToChatChannel (ichannelIdx, ichannelPrompt, iexistingText)
    NewChatWindow.UpdateCurrentChannel (ichannelIdx)
    
    local channelColor = ChatSettings.ChannelColors[ ichannelIdx ]
    if (not channelColor) then
		channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.SAY ]
	end
	if (ichannelIdx == 16) then
		ichannelPrompt = L"[Self]:"
		channelColor = {}
		channelColor.r, channelColor.g, channelColor.b = HueRGBAValue(1195)
    end

    TextEditBoxSetTextColor ("ChatWindowContainerTextInput", channelColor.r, channelColor.g, channelColor.b)

    if (iexistingText ~= nil) then
        TextEditBoxSetText("ChatWindowContainerTextInput", iexistingText)
    else
        TextEditBoxSetText("ChatWindowContainerTextInput", L"")  
    end
    WindowSetShowing("ChatWindowContainerTextInput", true)
    
    WindowAssignFocus( "ChatWindowContainerTextInput", true )

    LabelSetTextColor ("ChatWindowContainerChannelLabel", channelColor.r, channelColor.g, channelColor.b)
    
    LabelSetText ("ChatWindowContainerChannelLabel", ichannelPrompt)
end


function NewChatWindow.DoChatTextReplacement ()  
   
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
                
        for ixChannel, curChannell in pairs(ChatSettings.Channels) do 
			
            if (IsSlashCommandInChannel (firstWord, curChannell )) then

                -- Otherwise it's a regular channel, no crazy arguments...just do the switch
                NewChatWindow.SwitchToChatChannel (ixChannel, curChannell.labelText, restOfLine)
				
                return
                
            end
        end
         if (IsSlashCommandInChannel (firstWord, ChatSettings.Channels[SystemData.ChatLogFilters.GM])) then
			 NewChatWindow.SwitchToChatChannel (SystemData.ChatLogFilters.GM, ChatSettings.Channels[SystemData.ChatLogFilters.GM].labelText, restOfLine)
			 return   
         end
         if (wstring.find (wstring.lower(firstWord), L"/self")) then
			 NewChatWindow.SwitchToChatChannel (16, L"[Self]:", restOfLine)
			 return   
         end
    end
       
end

function NewChatWindow.Initialize()
	if (WindowData.PlayerStatus.PlayerId == 0) then
		return
	end
	NewChatWindow.Initialized = true
	ChatWindow.InitializeChannelMenuSelectionWindow()

	NewChatWindow.PlayerName = WindowData.MobileName[WindowData.PlayerStatus.PlayerId]
	
	for i = 0, NewChatWindow.maxTabs do
		NewChatWindow.LastMsg[i] = 1
		NewChatWindow.LastVis[i] = 1
		NewChatWindow.totalHeight[i] = 0
		NewChatWindow.Labels[i] = 0
		NewChatWindow.PrevLabels[i] = 0
	end
	
	NewChatWindow.SwitchOrder = {}
	NewChatWindow.SwitchOrder[1] = SystemData.ChatLogFilters.SAY
	NewChatWindow.SwitchOrder[2] = SystemData.ChatLogFilters.CUSTOM
	NewChatWindow.SwitchOrder[3] = SystemData.ChatLogFilters.PARTY
	NewChatWindow.SwitchOrder[4] = SystemData.ChatLogFilters.GUILD
	NewChatWindow.SwitchOrder[5] = SystemData.ChatLogFilters.ALLIANCE
	NewChatWindow.SwitchOrder[6] = SystemData.ChatLogFilters.GM
	
	
	for i= 1, NewChatWindow.maxTabs do
		NewChatWindow.ChannelsEnabled[i] = {}
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.SAY ]           = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.SAY,false )
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.WHISPER ]       = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.WHISPER,false )
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.PARTY ]         = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.PARTY,false ) 
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.GUILD ]         = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.GUILD,false ) 
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.ALLIANCE ]      = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.ALLIANCE,false ) 
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.EMOTE ]         = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.EMOTE,false ) 
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.YELL ]          = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.YELL,false )  
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.SYSTEM ]        = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.SYSTEM,false )  
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.PRIVATE ]       = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.PRIVATE,false )  
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.CUSTOM ]        = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.CUSTOM,false )  -- CHAT
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.GESTURE ]       = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.GESTURE,false )  
		NewChatWindow.ChannelsEnabled[i][ SystemData.ChatLogFilters.GM ]            = Interface.LoadBoolean( "ChannelsEnabled" .. i .. SystemData.ChatLogFilters.GM,true )  
		NewChatWindow.ChannelsEnabled[i][ 14 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. i .. 14,false )  -- DAMAGE FILTER
		NewChatWindow.ChannelsEnabled[i][ 15 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. i .. 15,false )  -- You See
		NewChatWindow.ChannelsEnabled[i][ 16 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. i .. 16,false )  -- Note to self
    end
    
    
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.SAY ]           = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.SAY,NewChatWindow.DefaultFont )
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.WHISPER ]       = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.WHISPER,NewChatWindow.DefaultFont )
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.PARTY ]         = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.PARTY,NewChatWindow.DefaultFont ) 
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.GUILD ]         = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.GUILD,NewChatWindow.DefaultFont ) 
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.ALLIANCE ]      = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.ALLIANCE,NewChatWindow.DefaultFont ) 
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.EMOTE ]         = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.EMOTE,NewChatWindow.DefaultFont ) 
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.YELL ]          = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.YELL,NewChatWindow.DefaultFont )  
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.SYSTEM ]        = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.SYSTEM,NewChatWindow.DefaultFont )  
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.PRIVATE ]       = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.PRIVATE,NewChatWindow.DefaultFont )  
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.CUSTOM ]        = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.CUSTOM,NewChatWindow.DefaultFont )  
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.GESTURE ]       = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.GESTURE,NewChatWindow.DefaultFont )  
    NewChatWindow.ChannelsFonts[ SystemData.ChatLogFilters.GM ]            = Interface.LoadNumber( "ChannelsFonts" .. SystemData.ChatLogFilters.GM,NewChatWindow.DefaultFont ) 
    NewChatWindow.ChannelsFonts[ 14 ]										 = Interface.LoadBoolean( "ChannelsFonts14",NewChatWindow.DefaultFont )  -- DAMAGE FILTER
    NewChatWindow.ChannelsFonts[ 15 ]										= Interface.LoadBoolean( "ChannelsFonts15",NewChatWindow.DefaultFont )  -- You See
    NewChatWindow.ChannelsFonts[ 16 ]										= Interface.LoadBoolean( "ChannelsFonts16",NewChatWindow.DefaultFont )  -- Note to self
    
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.SAY ]           = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.SAY,NewChatWindow.DefaultFontSize )
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.WHISPER ]       = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.WHISPER,NewChatWindow.DefaultFontSize )
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.PARTY ]         = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.PARTY,NewChatWindow.DefaultFontSize ) 
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.GUILD ]         = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.GUILD,NewChatWindow.DefaultFontSize ) 
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.ALLIANCE ]      = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.ALLIANCE,NewChatWindow.DefaultFontSize ) 
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.EMOTE ]         = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.EMOTE,NewChatWindow.DefaultFontSize ) 
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.YELL ]          = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.YELL,NewChatWindow.DefaultFontSize )  
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.SYSTEM ]        = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.SYSTEM,NewChatWindow.DefaultFontSize )  
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.PRIVATE ]       = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.PRIVATE,NewChatWindow.DefaultFontSize )  
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.CUSTOM ]        = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.CUSTOM,NewChatWindow.DefaultFontSize )  
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.GESTURE ]       = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.GESTURE,NewChatWindow.DefaultFontSize )  
    NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.GM ]            = Interface.LoadNumber( "ChannelsFontsSize" .. SystemData.ChatLogFilters.GM,NewChatWindow.DefaultFontSize ) 
    NewChatWindow.ChannelsFontsSize[ 14 ]											= Interface.LoadBoolean( "ChannelsFontsSize14" ,NewChatWindow.DefaultFontSize  )  -- DAMAGE FILTER
    NewChatWindow.ChannelsFontsSize[ 15 ]											= Interface.LoadBoolean( "ChannelsFontsSize15" ,NewChatWindow.DefaultFontSize  )  -- You see
    NewChatWindow.ChannelsFontsSize[ 16 ]											= Interface.LoadBoolean( "ChannelsFontsSize16" ,NewChatWindow.DefaultFontSize  )  -- Note to self
   
   NewChatWindow.BaseAlpha = Interface.LoadNumber( "NewChatWindowBaseAlpha",NewChatWindow.BaseAlpha )
	if (NewChatWindow.BaseAlpha < 0.01) then
		NewChatWindow.BaseAlpha = 0.01
	end 
  
   
   	NewChatWindow.autoHide = Interface.LoadBoolean( "NewChatWindowAutoHide",NewChatWindow.autoHide )
   	NewChatWindow.showMouseOver = Interface.LoadBoolean( "NewChatWindowshowMouseOver",NewChatWindow.showMouseOver )
   	NewChatWindow.waitTime = Interface.LoadNumber( "NewChatWindowwaitTime",NewChatWindow.waitTime )
   	NewChatWindow.ActiveTab = Interface.LoadNumber( "NewChatWindowActiveTab",NewChatWindow.ActiveTab )
   	NewChatWindow.TextFade = Interface.LoadBoolean( "NewChatWindowTextFade",NewChatWindow.TextFade )
   	NewChatWindow.TimeStamp = Interface.LoadBoolean( "NewChatWindowTimeStamp",NewChatWindow.TimeStamp )
	NewChatWindow.Locked = Interface.LoadBoolean( "NewChatWindowLocked",NewChatWindow.Locked )
	NewChatWindow.firstStart = Interface.LoadBoolean( "NewChatWindowfirstStart",NewChatWindow.firstStart )
	NewChatWindow.minTotDmg = Interface.LoadNumber( "NewChatWindowminTotDmg",NewChatWindow.minTotDmg )
	
	NewChatWindow.ShowSpells = Interface.LoadBoolean( "NewChatWindowShowSpells",NewChatWindow.ShowSpells )
	NewChatWindow.ShowSpellsCasting = Interface.LoadBoolean( "NewChatWindowShowSpellsCasting",NewChatWindow.ShowSpellsCasting )
	 
	NewChatWindow.ShowPerfection = Interface.LoadBoolean( "NewChatWindowShowPerfection",NewChatWindow.ShowPerfection )
	NewChatWindow.ShowMultiple = Interface.LoadBoolean( "NewChatWindowShowMultiple",NewChatWindow.ShowMultiple )
	 
	NewChatWindow.hideTag = Interface.LoadBoolean( "NewChatWindowhideTag",NewChatWindow.hideTag )
	 
	WindowSetShowing("NewChatWindowResizeButton", not NewChatWindow.Locked)

	 
	NewChatWindow.TabCount = Interface.LoadNumber( "NewChatWindowTabCount",NewChatWindow.TabCount )
	if (NewChatWindow.TabCount < 1) then
		NewChatWindow.TabCount = 1
	end
     
   SnapUtils.SnappableWindows["NewChatWindow"] = true
   
   WindowSetDimensions("NewChatWindow", 400, 200)
	
	WindowUtils.RestoreWindowPosition("NewChatWindow", true)
	NewChatWindow.OnResizeEnd(NewChatWindow.WindowName)
	if Interface.NewChatFirstPositioning then
		WindowClearAnchors("NewChatWindow")
		WindowAddAnchor("NewChatWindow", "bottomleft", "ResizeWindow", "bottomleft", 0, -40)
		local x, y= WindowGetOffsetFromParent("NewChatWindow")
		WindowClearAnchors("NewChatWindow")
		WindowSetOffsetFromParent("NewChatWindow", x,y)
		Interface.NewChatFirstPositioning = nil
	end
	
	CreateWindowFromTemplate( "NewChatOptionButtons", "NewChatButtons", "NewChatSettingsWindowScrollChildText" )
	
	local barName =	"BaseAlpha"
	CreateWindowFromTemplate( barName, "SliderItemTemplate", "NewChatSettingsWindowScrollChildText" )
	WindowAddAnchor( barName, "topleft", "NewChatSettingsWindowScrollChildText", "topleft", 35, 100 )
	LabelSetText( barName .. "Text", GetStringFromTid(1155187))
	SliderBarSetCurrentPosition(barName .. "SliderBar", NewChatWindow.BaseAlpha )
	LabelSetText( barName .. "Val", L"" .. NewChatWindow.BaseAlpha)
	
	local templatename = "AutoHideCheck"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("AutoHideCheckButton", NewChatWindow.autoHide)
	LabelSetText(templatename.."Label", GetStringFromTid(1155188))
	WindowAddAnchor(templatename, "bottomleft", "BaseAlpha", "topleft", 0, 20)
	
	barName = "FadeDelay"
	CreateWindowFromTemplate( barName, "SliderItemTemplate", "NewChatSettingsWindowScrollChildText" )
	WindowAddAnchor( barName, "bottomleft", "AutoHideCheck", "topleft", 0, 40 )
	LabelSetText( barName .. "Text", GetStringFromTid(1155189))
	SliderBarSetCurrentPosition(barName .. "SliderBar", NewChatWindow.waitTime / 20 )
	LabelSetText( barName .. "Val", L"" .. NewChatWindow.waitTime)
	
	
	templatename = "ShowMouseOver"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("ShowMouseOverButton", NewChatWindow.showMouseOver)
	LabelSetText(templatename.."Label", GetStringFromTid(1155190))
	WindowAddAnchor(templatename, "bottomleft", "FadeDelay", "topleft", 0, 40)
	
	templatename = "FadeText"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("FadeTextButton", NewChatWindow.TextFade)
	LabelSetText(templatename.."Label", GetStringFromTid(1155191))
	WindowAddAnchor(templatename, "bottomleft", "ShowMouseOver", "topleft", 0 , 20)
	
	templatename = "TimeStamp"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("TimeStampButton", NewChatWindow.TimeStamp)
	LabelSetText(templatename.."Label", GetStringFromTid(1155192))
	WindowAddAnchor(templatename, "bottomleft", "FadeText", "topleft", 0 , 20)
	
	templatename = "LockWindow"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("LockWindowButton", NewChatWindow.Locked)
	LabelSetText(templatename.."Label", GetStringFromTid(1155193))
	WindowAddAnchor(templatename, "bottomleft", "TimeStamp", "topleft", 0 , 20)
	
	templatename = "LockLine"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("LockLineButton", Interface.LockChatLine)
	LabelSetText(templatename.."Label", GetStringFromTid(1155275))
	WindowAddAnchor(templatename, "bottomleft", "LockWindow", "topleft", 0 , 20)
	
	
	barName = "MinTotDamage"
	CreateWindowFromTemplate( barName, "SliderItemTemplate", "NewChatSettingsWindowScrollChildText" )
	WindowAddAnchor( barName, "bottomleft", "LockLine", "topleft", 0, 40 )
	LabelSetText( barName .. "Text", GetStringFromTid(1155194))
	SliderBarSetCurrentPosition(barName .. "SliderBar", NewChatWindow.minTotDmg / 1000 )
	LabelSetText( barName .. "Val", L"" .. NewChatWindow.minTotDmg)
	
	
	templatename = "DivYouSee"
	CreateWindowFromTemplate( templatename, "SubSectionLabelTemplate", "NewChatSettingsWindowScrollChildText" )

	LabelSetText(templatename.."Label", GetStringFromTid(1155195))
	WindowAddAnchor(templatename, "bottomleft", "MinTotDamage", "topleft", 0 , 40)
	
	NewChatWindow.SavedFilter[1] = false
	
	for i = 2, table.getn(NewChatWindow.Filter) do
		local templatename = "YouSeeFilterCheckButton_"..i
		CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
		ButtonSetCheckButtonFlag( templatename.."Button", true )
		NewChatWindow.SavedFilter[i] = Interface.LoadBoolean( "NewChatYSFilter"..i, NewChatWindow.SavedFilter[i] )
		ButtonSetPressedFlag(templatename.."Button", NewChatWindow.SavedFilter[i])
		LabelSetText(templatename.."Label", NewChatWindow.Filter[i])
		if (i == 10) then
			LabelSetTextColor(templatename.."Label", NameColor.TextColors[NameColor.Notoriety.MURDERER].r, NameColor.TextColors[NameColor.Notoriety.MURDERER].g, NameColor.TextColors[NameColor.Notoriety.MURDERER].b)
		end
		if i < 9 then
			NameColor.UpdateLabelNameColor(templatename.."Label", i)
		end
		
		if (i == 2) then
			WindowAddAnchor(templatename, "topleft", "DivYouSee", "topleft", 0, 40)
		else
			WindowAddAnchor(templatename, "bottomleft", "YouSeeFilterCheckButton_"..i-1, "topleft", 0, -5)
		end
	end
	
	templatename = "DivMsgFilters"
	CreateWindowFromTemplate( templatename, "SubSectionLabelTemplate", "NewChatSettingsWindowScrollChildText" )
	LabelSetText(templatename.."Label", GetStringFromTid(1155196))
	WindowAddAnchor(templatename, "bottomleft", "YouSeeFilterCheckButton_" .. table.getn(NewChatWindow.Filter), "topleft", 0 , 40)
	
	templatename = "Spells"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("SpellsButton", NewChatWindow.ShowSpells)
	LabelSetText(templatename.."Label", GetStringFromTid(1155197))
	WindowAddAnchor(templatename, "bottomleft", "DivMsgFilters", "topleft", 0 , 40)
	
	templatename = "SpellsCasting"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("SpellsCastingButton", NewChatWindow.ShowSpellsCasting)
	LabelSetText(templatename.."Label", GetStringFromTid(1155198))
	WindowAddAnchor(templatename, "bottomleft", "Spells", "topleft", 0 , 10)
	
	templatename = "PerfectionMsgs"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("PerfectionMsgsButton", NewChatWindow.ShowPerfection)
	LabelSetText(templatename.."Label", GetStringFromTid(1155199))
	WindowAddAnchor(templatename, "bottomleft", "SpellsCasting", "topleft", 0 , 10)
	
	templatename = "PreventsMultiple"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("PreventsMultipleButton", NewChatWindow.ShowMultiple)
	LabelSetText(templatename.."Label", GetStringFromTid(1155200))
	WindowAddAnchor(templatename, "bottomleft", "PerfectionMsgs", "topleft", 0 , 10)
	
	templatename = "HideTags"
	CreateWindowFromTemplate( templatename, "LabelCheckButton", "NewChatSettingsWindowScrollChildText" )
	ButtonSetCheckButtonFlag( templatename.."Button", true )
	ButtonSetPressedFlag("HideTagsButton", NewChatWindow.hideTag)
	LabelSetText(templatename.."Label", GetStringFromTid(1155201))
	WindowAddAnchor(templatename, "bottomleft", "PreventsMultiple", "topleft", 0 , 10)
	
	
	
	NewChatWindow.InitializeSettings()
	
	NewChatWindow.LoadTabs()
	
	NewChatWindow.SetVisible()

	--NewChatWindow.UpdateLog()
	
end

function NewChatWindow.LoadTabs()
	local first = 0
	local row = 0
	local w, h = WindowGetDimensions("NewChatWindow")
	local bookmrkxRow = math.floor(w/90)-- 4
	local bookmrkxCount = 0
	for i = 1, NewChatWindow.maxTabs do
		local templatename = "Bookmark" .. i
		if (DoesWindowNameExist(templatename)) then
			DestroyWindow(templatename)
		end
		if (DoesWindowNameExist("NewChatWindow" .. i)) then
			DestroyWindow("NewChatWindow" .. i)
		end
		if (DoesWindowNameExist("NewChatWindowBookmark" .. i)) then
			DestroyWindow("NewChatWindowBookmark" .. i)
		end
	end
	NewChatWindow.LastDock = 0
	for i = 1, NewChatWindow.TabCount do
		local templatename = "Bookmark" .. i
		CreateWindowFromTemplate( templatename, "BookmarkTemplate", "Root" )
		WindowSetDimensions(templatename, 82, 30)
		local txt = L"ChatTab"
		if (NewChatWindow.firstStart and i == 1) then
			Interface.SaveBoolean( "NewChatWindowfirstStart",false )
			txt = L"Journal"
			Interface.SaveWString( "NewChatWindowTabName" .. i ,txt )
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.SAY,true )
			 Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.WHISPER,true )
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.PARTY,true ) 
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GUILD,true ) 
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.ALLIANCE,true ) 
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.EMOTE,true ) 
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.YELL,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.SYSTEM,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.PRIVATE,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.CUSTOM,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GESTURE,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GM,true )  
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. 14,true )  -- DAMAGE FILTER
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. 15,true )  -- You See
			Interface.SaveBoolean( "ChannelsEnabled" .. 1 .. 16,true )  -- Note to self
			
			NewChatWindow.ChannelsEnabled[1] = {}
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.SAY ]           = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.SAY,true )
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.WHISPER ]       = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.WHISPER,true )
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.PARTY ]         = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.PARTY,true ) 
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.GUILD ]         = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GUILD,true ) 
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.ALLIANCE ]      = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.ALLIANCE,true ) 
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.EMOTE ]         = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.EMOTE,true ) 
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.YELL ]          = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.YELL,true )  
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.SYSTEM ]        = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.SYSTEM,true )  
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.PRIVATE ]       = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.PRIVATE,true )  
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.CUSTOM ]        = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.CUSTOM,true )  
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.GESTURE ]       = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GESTURE,true )  
			NewChatWindow.ChannelsEnabled[1][ SystemData.ChatLogFilters.GM ]            = Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. SystemData.ChatLogFilters.GM,true )  
			NewChatWindow.ChannelsEnabled[1][ 14 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. 14,true )  -- DAMAGE FILTER
			NewChatWindow.ChannelsEnabled[1][ 15 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. 15,true )  -- You See
			NewChatWindow.ChannelsEnabled[1][ 16 ]										= Interface.LoadBoolean( "ChannelsEnabled" .. 1 .. 16,true )  -- Note to self
		end
		if (SystemData.Settings.Language.type == SystemData.Settings.Language.LANGUAGE_ENU) then
			LabelSetFont(templatename.."Text",  "Arial_Black_Shadow_15", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)
		else
			LabelSetFont(templatename.."Text",  "MyriadPro_16", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)
			WindowClearAnchors(templatename.."Text")
			WindowAddAnchor(templatename.."Text", "topleft", templatename, "topleft", 5 , 3)
			
		end
		LabelSetText(templatename.."Text", Interface.LoadWString( "NewChatWindowTabName" .. i ,txt ))
		WindowClearAnchors(templatename)
		NewChatWindow.TabStatus[i] = { extracted = Interface.LoadBoolean( "NewChatWindowTabExtracted" .. i, false ) }
		if (NewChatWindow.TabStatus[i].extracted == true) then
			CreateWindowFromTemplate( "NewChatWindow" .. i, "NewChatWindowBookmarsk" .. i, "Root" )
			SnapUtils.SnappableWindows["NewChatWindow" .. i] = true
	   
		   WindowSetDimensions("NewChatWindow" .. i, 400, 200)
			
			WindowUtils.RestoreWindowPosition("NewChatWindow" .. i, true)
			WindowSetId("NewChatWindow" .. i, i)
			NewChatWindow.OnResizeEnd("NewChatWindow" .. i, true)
		
			--WindowSetParent("Bookmark"..i, "NewChatWindow"  .. i )
			WindowAddAnchor("Bookmark"..i, "topleft", "NewChatWindow" .. i, "topleft", 0 , -30)
		else
			if (first <= 0) then
				first = i
			end

			if (bookmrkxCount == bookmrkxRow) then
				row = row - 1
				bookmrkxCount = 0
			end
			if (NewChatWindow.LastDock <= 0 or bookmrkxCount == 0) then

				WindowClearAnchors(templatename)
				WindowAddAnchor(templatename, "topleft", "NewChatWindow", "topleft", 0 , (row * 35) -30)
				NewChatWindow.LastDock = i
				bookmrkxCount =  bookmrkxCount +1
			else
				if (not NewChatWindow.TabStatus[NewChatWindow.LastDock].extracted) then
					WindowClearAnchors(templatename)
					WindowAddAnchor(templatename, "topright", "Bookmark" .. NewChatWindow.LastDock, "topleft", 10 , 0)
					NewChatWindow.LastDock = i
					bookmrkxCount = bookmrkxCount + 1
				else
					for j = 1, i-1 do
						if(not NewChatWindow.TabStatus[j].extracted and j > NewChatWindow.LastDock) then
							WindowClearAnchors(templatename)
							WindowAddAnchor(templatename, "topright", "Bookmark" .. j, "topleft", 10 , 0)
							NewChatWindow.LastDock = j
							bookmrkxCount = bookmrkxCount + 1
							break
						end
					end
				end
			end
		end
	end

	 NewChatWindow.ShowAgain(true)
	  local extTabs = 0
	for j = 1, NewChatWindow.maxTabs do
		local templatename = "NewChatWindow" .. j .."ResizeButton"
		if (DoesWindowNameExist( templatename)) then
			WindowSetShowing(templatename, not NewChatWindow.Locked)
			if (NewChatWindow.TabStatus[j].extracted) then
				extTabs = extTabs +1
			end
		end
	end
	if (NewChatWindow.TabCount - extTabs > 1) then
		LabelSetTextColor("Bookmark" .. NewChatWindow.ActiveTab .. "Text", NewChatWindow.ActiveColor.r, NewChatWindow.ActiveColor.g, NewChatWindow.ActiveColor.b)
	else
		NewChatWindow.ActiveTab = first
	end
end

function NewChatWindow.Shutdown()
    WindowUtils.SaveWindowPosition(SystemData.ActiveWindow.name, true)
    SnapUtils.SnappableWindows[SystemData.ActiveWindow.name] = nil
    
end

function NewChatWindow.BookmarkContext()
	
	if (WindowGetAlpha(SystemData.ActiveWindow.name) < 0.2) then
		return
	end
	local bookmarkIndex = string.gsub(SystemData.ActiveWindow.name, "Bookmark", "")
	bookmarkIndex = tonumber(bookmarkIndex)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155203),0,"rename",bookmarkIndex,false)
	local enable = 0
	if (NewChatWindow.TabCount >= NewChatWindow.maxTabs) then
		enable = 1
	end
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155202),enable,"add",bookmarkIndex,false)
	
	enable = 0
	if (NewChatWindow.TabCount <= 1) then
		enable = 1
	end
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155207),enable,"remove",bookmarkIndex,false)
	
	
	if (NewChatWindow.TabStatus[bookmarkIndex] and NewChatWindow.TabStatus[bookmarkIndex].extracted) then
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155205),0,"reintegrate",bookmarkIndex,false)
	else
		if (NewChatWindow.LastDock > 1) then
			ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155204),0,"extract",bookmarkIndex,false)
		else
			ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155204),1,"extract",bookmarkIndex,false)
		end
	end
	
	
	
	local subMenu = {}	
	for i = 1, table.getn(ChatSettings.Channels) do
		local val = { str = ChatSettings.Channels[i].name,flags=0,param=bookmarkIndex, returnCode=i,pressed=NewChatWindow.ChannelsEnabled[bookmarkIndex][i]}
		table.insert(subMenu, val)
	end
	
	local val = { str = GetStringFromTid(1155206),flags=0,param=bookmarkIndex, returnCode=14,pressed=NewChatWindow.ChannelsEnabled[bookmarkIndex][14]}
	table.insert(subMenu, val)
	local val = { str = GetStringFromTid(1155208),flags=0,param=bookmarkIndex, returnCode=15,pressed=NewChatWindow.ChannelsEnabled[bookmarkIndex][15]}
	table.insert(subMenu, val)
	local val = { str = GetStringFromTid(1155209),flags=0,param=bookmarkIndex, returnCode=16,pressed=NewChatWindow.ChannelsEnabled[bookmarkIndex][16]}
	table.insert(subMenu, val)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155210),0,0,"null",false,subMenu)
		
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155211),0,"save",bookmarkIndex,false)
	
	
	ContextMenu.ActivateLuaContextMenu(NewChatWindow.BookmarkContextMenuCallback)
end

function NewChatWindow.BookmarkContextMenuCallback( returnCode, param )

	if (returnCode == "extract") then
	
		NewChatWindow.TabStatus[param] = { extracted = true  }
		Interface.SaveBoolean( "NewChatWindowTabExtracted" .. param, NewChatWindow.TabStatus[param].extracted )
		if (param == NewChatWindow.ActiveTab) then
			NewChatWindow.ActiveTab = 1
		end
		NewChatWindow.LoadTabs()
	elseif (returnCode == "save") then
		local output = L"\r\n"
		for i = 1, table.getn(NewChatWindow.Messages) do
			local text = NewChatWindow.Messages[i].text
			if (not NewChatWindow.ChannelsEnabled[param][NewChatWindow.Messages[i].channel] or NewChatWindow.Messages[i].ignore) then
				continue
			end
			if (NewChatWindow.Messages[i].channel ~= SystemData.ChatLogFilters.SYSTEM and NewChatWindow.Messages[i].sourceName and NewChatWindow.Messages[i].sourceName ~= L"" ) then
				text = L"[" .. NewChatWindow.Messages[i].sourceName .. L"]: " .. NewChatWindow.Messages[i].text
			end
			text = L"[" .. NewChatWindow.Messages[i].timeStamp .. L"] " .. text
			output = output .. L"\r\n" .. text
		end

		if( Interface.Clock.h < 10) then
			clockhstr = "0"..tostring(Interface.Clock.h)
		else
			clockhstr = tostring(Interface.Clock.h)
		end
		if( Interface.Clock.m < 10) then
			clockmstr = "0"..tostring(Interface.Clock.m)
		else
			clockmstr = tostring(Interface.Clock.m)
		end
		if( Interface.Clock.s < 10) then
			clocksstr = "0"..tostring(Interface.Clock.s)
		else
			clocksstr = tostring(Interface.Clock.s)
		end
		local clockstring = clockhstr.."."..clockmstr.."."..clocksstr
		
		TextLogCreate( "NewChatLog", 1 )
		local path = "logs/" .."[" .. clockstring .. "] " ..  WStringToString(Interface.LoadWString( "NewChatWindowTabName" .. param ,L"ChatTab" )) .. ".txt"
		TextLogSetIncrementalSaving( "NewChatLog", true, path )
		TextLogSetEnabled( "NewChatLog", true )
		TextLogAddEntry( "NewChatLog", 1,  output )
		TextLogSetEnabled("NewChatLog", false)
		TextLogDestroy("NewChatLog")
		
	elseif (returnCode == "reintegrate") then
	
		NewChatWindow.TabStatus[param] = { extracted = false  }
		Interface.SaveBoolean( "NewChatWindowTabExtracted" .. param, NewChatWindow.TabStatus[param].extracted )
		NewChatWindow.LoadTabs()
	elseif (returnCode == "rename") then
		local rdata = {title=GetStringFromTid(1155203), subtitle=L"Choose the new tab name:", callfunction=NewChatWindow.BookmarkRename, id=param}
		RenameWindow.Create(rdata)
	elseif (returnCode == "remove") then
		NewChatWindow.TabCount = NewChatWindow.TabCount - 1
		Interface.SaveNumber( "NewChatWindowTabCount",NewChatWindow.TabCount )
		for j = param + 1, NewChatWindow.maxTabs do
			Interface.SaveWString( "NewChatWindowTabName" .. j-1 ,Interface.LoadWString( "NewChatWindowTabName" .. j ,L"ChatTab" ) )
			NewChatWindow.TabStatus[j-1] = false
			Interface.SaveBoolean( "NewChatWindowTabExtracted" .. j-1, false )
		end
		for j = 1, NewChatWindow.maxTabs do
			NewChatWindow.TabStatus[j] = { extracted = false  }
			Interface.SaveBoolean( "NewChatWindowTabExtracted" .. j, NewChatWindow.TabStatus[j].extracted )
		end
		if (DoesWindowNameExist("NewChatWindow" .. param)) then
			DestroyWindow("NewChatWindow" .. param)
		end
		NewChatWindow.LoadTabs()
	elseif (returnCode == "add") then
		NewChatWindow.TabCount = NewChatWindow.TabCount + 1
		Interface.SaveNumber( "NewChatWindowTabCount",NewChatWindow.TabCount )
		Interface.SaveWString( "NewChatWindowTabName" .. NewChatWindow.TabCount ,L"ChatTab" )
		for i = 1, table.getn(ChatSettings.Channels) do
			NewChatWindow.ChannelsEnabled[NewChatWindow.TabCount][i] = false or i == SystemData.ChatLogFilters.GM
			Interface.SaveBoolean( "ChannelsEnabled".. NewChatWindow.TabCount .. i,NewChatWindow.ChannelsEnabled[NewChatWindow.TabCount][i] ) 
		end
		NewChatWindow.LoadTabs()
	elseif( tonumber(returnCode) ) then
		NewChatWindow.ChannelsEnabled[param][returnCode] = not NewChatWindow.ChannelsEnabled[param][returnCode]
		Interface.SaveBoolean( "ChannelsEnabled".. param .. returnCode,NewChatWindow.ChannelsEnabled[param][returnCode] ) 
		NewChatWindow.ClearAll()
		NewChatWindow.UpdateLog()
	end
end

function NewChatWindow.BookmarkRename(id, text)
	if (wstring.len(text) <= 0) then
		text = L"ChatTab"
	end
	Interface.SaveWString( "NewChatWindowTabName" .. id ,text )
	local templatename = "Bookmark" .. id
	LabelSetText(templatename.."Text", Interface.LoadWString( "NewChatWindowTabName" .. id ,L"ChatTab" ))
end


function NewChatWindow.LabelOnMouseOver()
	
end

function NewChatWindow.OnResizeBegin()
	local windowName = WindowUtils.GetActiveDialog()
	local widthMin = 100
	local heightMin = 150
    WindowUtils.BeginResize( windowName, "topleft", widthMin, heightMin, false, NewChatWindow.OnResizeEnd)
end


function NewChatWindow.OnResizeEnd(curWindow, forced)
	local windowWidth, windowHeight = WindowGetDimensions(curWindow)
	
	if(windowWidth > NewChatWindow.WINDOW_WIDTH_MAX) then
		windowWidth = NewChatWindow.WINDOW_WIDTH_MAX
	end
	
	if(windowHeight > NewChatWindow.WINDOW_HEIGHT_MAX) then
		windowHeight = NewChatWindow.WINDOW_HEIGHT_MAX
	end
	

	WindowSetDimensions(curWindow, windowWidth, windowHeight)
	
	
	--local topWidth, topHeight = WindowGetDimensions(curWindow.."Top")
	--WindowSetDimensions(curWindow.."Top",windowWidth + 30,topHeight)
	--local bottomWidth, bottomHeight = WindowGetDimensions(curWindow.."Bottom")
	--WindowSetDimensions(curWindow.."Bottom",windowWidth + 30,bottomHeight)
	
	local id = WindowGetId(curWindow)
	if (id and id > 0) then
		local Width,Height  = WindowGetDimensions("NewChatWindowBookmark" .. id .. "ScrollChildText")
		WindowSetDimensions("NewChatWindowBookmark" .. id, windowWidth - 10, windowHeight - 100)
		WindowSetDimensions("NewChatWindowBookmark" .. id .. "ScrollChild", windowWidth - 10, windowHeight - 95)
		
		WindowSetDimensions("NewChatWindowBookmark" .. id .. "ScrollChildText", windowWidth - 10, Height)
		
		ScrollWindowSetOffset( "NewChatWindowBookmark" .. id, 0 )
		ScrollWindowUpdateScrollRect( "NewChatWindowBookmark" .. id )
	else
		local Width,Height  = WindowGetDimensions("NewChatWindowJournalWindowScrollChildText")
		WindowSetDimensions("NewChatWindowJournalWindow", windowWidth - 10, windowHeight - 100)
		WindowSetDimensions("NewChatWindowJournalWindowScrollChild", windowWidth - 10, windowHeight - 95)
		
		WindowSetDimensions("NewChatWindowJournalWindowScrollChildText", windowWidth - 10, Height)
		
		ScrollWindowSetOffset( "NewChatWindowJournalWindow", 0 )
		ScrollWindowUpdateScrollRect( "NewChatWindowJournalWindow" )
	end
	if not forced then
		NewChatWindow.ClearAll()
		NewChatWindow.LoadTabs()
		NewChatWindow.UpdateLog()
	end
end

function NewChatWindow.SwitchTab()
	if (WindowGetAlpha(SystemData.ActiveWindow.name) < 0.2) then
		return
	end
	local cleanName = string.gsub(SystemData.ActiveWindow.name, "Bookmark", "")
	cleanName = string.gsub(cleanName, "IMG", "")
	cleanName = string.gsub(cleanName, "Text", "")
	
	if (NewChatWindow.TabStatus[tonumber(cleanName)].extracted) then
		return
	end
	NewChatWindow.ActiveTab = tonumber(cleanName)
	Interface.SaveNumber( "NewChatWindowActiveTab",NewChatWindow.ActiveTab )
	for i = 1, NewChatWindow.TabCount do
		if (DoesWindowNameExist("Bookmark" .. i .. "Text")) then
			if (i == NewChatWindow.ActiveTab) then
				local extTabs = 0
				for j = 1, NewChatWindow.maxTabs do
					local templatename = "NewChatWindow" .. j .."ResizeButton"
					if (DoesWindowNameExist( templatename)) then
						WindowSetShowing(templatename, not NewChatWindow.Locked)

						if (NewChatWindow.TabStatus[j].extracted) then
							extTabs = extTabs +1
						end
					end
				end
				if (NewChatWindow.TabCount - extTabs > 1) then
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.ActiveColor.r, NewChatWindow.ActiveColor.g, NewChatWindow.ActiveColor.b)
				else
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
				end
			else
				LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
			end
		end
	end
	NewChatWindow.ClearAll()
	NewChatWindow.UpdateLog()
end

function NewChatWindow.ClearAll()
	NewChatWindow.LastMsg[0] = table.getn(NewChatWindow.Messages) - NewChatWindow.messagesBuffCap
	if (NewChatWindow.LastMsg[0] < 1) then
		NewChatWindow.LastMsg[0] = 1
	end
	NewChatWindow.LastVis[0] = 1
	for i = 1, table.getn(NewChatWindow.Messages) do
		if (DoesWindowNameExist("MainLog"..i)) then
			DestroyWindow("MainLog"..i)
		end
	end
	NewChatWindow.totalHeight[0] = 0
	NewChatWindow.Labels[0] = 0
	local Width, Height = WindowGetDimensions("NewChatWindowJournalWindowScrollChildText")
	WindowSetDimensions("NewChatWindowJournalWindowScrollChildText", Width, 0  )
	ScrollWindowUpdateScrollRect( "NewChatWindowJournalWindow" )
	
	for i = 1, NewChatWindow.maxTabs do
		local templatename = "NewChatWindow" .. i
		if (DoesWindowNameExist(templatename)) then
			NewChatWindow.LastMsg[i] = table.getn(NewChatWindow.Messages) - NewChatWindow.messagesBuffCap
			if (NewChatWindow.LastMsg[i] < 1) then
				NewChatWindow.LastMsg[i] = 1
			end
			NewChatWindow.LastVis[i] = 1
			for j = 1, table.getn(NewChatWindow.Messages) do
				if (DoesWindowNameExist(templatename .. "Log"..j)) then
					DestroyWindow(templatename .. "Log"..j)
				end
			end
			NewChatWindow.totalHeight[i] = 0
			NewChatWindow.Labels[i] = 0
			local Width, Height = WindowGetDimensions("NewChatWindowBookmark" .. i .. "ScrollChildText")
			WindowSetDimensions("NewChatWindowBookmark" .. i .. "ScrollChildText", Width, 0  )
			ScrollWindowUpdateScrollRect( "NewChatWindowBookmark" .. i )
		end
	end
end

function NewChatWindow.OnOpenChannelMenu()
	Tooltips.ClearTooltip()

    if (WindowGetShowing("NewChatChannelSelectionWindow") == true)
    then
        WindowSetShowing("NewChatChannelSelectionWindow", false)
        WindowAssignFocus( "NewChatChannelSelectionWindow", false )
    else
        WindowClearAnchors( "NewChatChannelSelectionWindow" )
        WindowAddAnchor( "NewChatChannelSelectionWindow", "bottomright", "NewChatWindowInputTextButton", "bottomleft", 0, 0 )    
        WindowSetShowing("NewChatChannelSelectionWindow", true)
        WindowSetShowing( "NewChatChannelSelectionWindowSelection", false )
        WindowAssignFocus( "NewChatChannelSelectionWindow", true )
    end
end

function ChatWindow.InitializeChannelMenuSelectionWindow()
    CreateWindow( "NewChatChannelSelectionWindow", false )
    
    -- Say channel
    local channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.SAY ]
    WindowSetId( "NewChatChannelSelectionWindowSayButton", SystemData.ChatLogFilters.SAY)
    ButtonSetText( "NewChatChannelSelectionWindowSayButton", L"/Say" ) 
    ButtonSetTextColor("NewChatChannelSelectionWindowSayButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowSayButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowSayButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Yell channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.YELL ]
    WindowSetId( "NewChatChannelSelectionWindowYellButton", SystemData.ChatLogFilters.YELL)
    ButtonSetText("NewChatChannelSelectionWindowYellButton", L"/Yell" )
    ButtonSetTextColor("NewChatChannelSelectionWindowYellButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowYellButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowYellButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Guild channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.GUILD ]
    WindowSetId( "NewChatChannelSelectionWindowGuildButton", SystemData.ChatLogFilters.GUILD )
    ButtonSetText("NewChatChannelSelectionWindowGuildButton", L"/Guild" )
    ButtonSetTextColor("NewChatChannelSelectionWindowGuildButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGuildButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGuildButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Party channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.PARTY ]
    WindowSetId( "NewChatChannelSelectionWindowPartyButton", ChatSettings.Channels[SystemData.ChatLogFilters.PARTY].id )
    ButtonSetText("NewChatChannelSelectionWindowPartyButton", L"/Party" )
    ButtonSetTextColor("NewChatChannelSelectionWindowPartyButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowPartyButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowPartyButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Alliance channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.ALLIANCE ]
    WindowSetId( "NewChatChannelSelectionWindowAllianceButton", ChatSettings.Channels[SystemData.ChatLogFilters.ALLIANCE].id )
    ButtonSetText("NewChatChannelSelectionWindowAllianceButton", L"/Alliance" )
    ButtonSetTextColor("NewChatChannelSelectionWindowAllianceButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowAllianceButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowAllianceButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Chat channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.CUSTOM ]
    WindowSetId( "NewChatChannelSelectionWindowChatButton", SystemData.ChatLogFilters.CUSTOM)
    ButtonSetText("NewChatChannelSelectionWindowChatButton", L"/Chat (Global)" )
    ButtonSetTextColor("NewChatChannelSelectionWindowChatButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowChatButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowChatButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowChatButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- GM channel
    channelColor = ChatSettings.ChannelColors[ SystemData.ChatLogFilters.GM ]
    WindowSetId( "NewChatChannelSelectionWindowGMButton", SystemData.ChatLogFilters.GM)
    ButtonSetText("NewChatChannelSelectionWindowGMButton", L"/GM" )
    ButtonSetTextColor("NewChatChannelSelectionWindowGMButton", Button.ButtonState.NORMAL, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGMButton", Button.ButtonState.HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGMButton", Button.ButtonState.PRESSED, channelColor.r, channelColor.g, channelColor.b)
    ButtonSetTextColor("NewChatChannelSelectionWindowGMButton", Button.ButtonState.PRESSED_HIGHLIGHTED, channelColor.r, channelColor.g, channelColor.b)
    
    -- Self channel
    WindowSetId( "NewChatChannelSelectionWindowSelfButton", 16)
    ButtonSetText("NewChatChannelSelectionWindowSelfButton", L"/Self" )
	 ButtonSetTextColor("NewChatChannelSelectionWindowSelfButton", Button.ButtonState.NORMAL, 192, 192, 248)
    ButtonSetTextColor("NewChatChannelSelectionWindowSelfButton", Button.ButtonState.HIGHLIGHTED, 192, 192, 248)
    ButtonSetTextColor("NewChatChannelSelectionWindowSelfButton", Button.ButtonState.PRESSED, 192, 192, 248)
    ButtonSetTextColor("NewChatChannelSelectionWindowSelfButton", Button.ButtonState.PRESSED_HIGHLIGHTED, 192, 192, 248)
end

function NewChatWindow.UpdateLog()
	ok, err = pcall(NewChatWindow.UpdateLogR)
	Interface.ErrorTracker(ok, err)
end

function NewChatWindow.UpdateLogR()
	
	if (NewChatWindow.blockUpdate == true) then
		NewChatWindow.UpdateReq = true
		return
	end
	NewChatWindow.blockUpdate = true
	
	local autoScroll = true
	
	if (NewChatWindow.LastVis[0] and DoesWindowNameExist("MainLog"..NewChatWindow.LastVis[0])) then
		local dontCare, maxOffset = WindowGetDimensions("NewChatWindowJournalWindow")
		local elementX,elementY = WindowGetScreenPosition("MainLog"..NewChatWindow.LastVis[0])
		local parentX,parentY = WindowGetScreenPosition("NewChatWindowJournalWindow")
		local scrollOffset = elementY - parentY

		if( scrollOffset > maxOffset ) then
			autoScroll = false
		end
	end
	
	local clAll = false
	if (NewChatWindow.Labels[0] and NewChatWindow.Labels[0] > NewChatWindow.messagesBuffCap * 2) then
		NewChatWindow.ClearAll()
		clAll = true
	end
	if not clAll then
		for j = 1, NewChatWindow.maxTabs do
			if (NewChatWindow.Labels[j] and NewChatWindow.Labels[j] > NewChatWindow.messagesBuffCap) then
				NewChatWindow.ClearAll()
				break
			end
		end
	end
	
	local Width, Height = WindowGetDimensions("NewChatWindowJournalWindowScrollChildText")

	WindowClearAnchors("NewChatWindowJournalWindow")
	WindowAddAnchor("NewChatWindowJournalWindow", "topleft","NewChatWindow", "topleft", 5, 10 )
	WindowAddAnchor("NewChatWindowJournalWindow", "bottomright","NewChatWindow", "bottomright", -2, -10 )
	WindowSetLayer("NewChatWindowJournalWindow", Window.Layers.DEFAULT	)	
	WindowSetParent("NewChatWindowJournalWindow", "NewChatWindow")
	
	if (NewChatWindow.LastMsg[0]) then
		for i = NewChatWindow.LastMsg[0], table.getn(NewChatWindow.Messages) do
			if (not NewChatWindow.ChannelsEnabled[NewChatWindow.ActiveTab][NewChatWindow.Messages[i].channel] or NewChatWindow.Messages[i].ignore) then
				continue
			end
			
			if(NewChatWindow.Messages[i].channel == 15) then
				local passa = NewChatWindow.SavedFilter[NewChatWindow.Messages[i].Notoriety+1]
				if (not NewChatWindow.SavedFilter[9] and MobilesOnScreen.IsFarm(NewChatWindow.Messages[i].sourceName)) then
						passa = false
				end
				if (not NewChatWindow.SavedFilter[10] and MobilesOnScreen.IsSummon(NewChatWindow.Messages[i].sourceName)) then
						passa = false
				end
				if not passa then
					continue
				end
			end
			if (NewChatWindow.Messages[i].channel == 16) then
				NewChatWindow.Messages[i].color = {r=192, g=192, b=248}
				NewChatWindow.Messages[i].sourceName = GetStringFromTid(3000610) -- Note to Self:
			end
			
		
			CreateWindowFromTemplate( "MainLog"..i, "JournalItem", "NewChatWindowJournalWindowScrollChildText" )

			
			WindowSetParent("MainLog"..i, "NewChatWindowJournalWindowScrollChildText")
			
		
			WindowSetDimensions("MainLog"..i, Width - 15 , 20)
			if (NewChatWindow.Messages[i].channel == 15) then
				WindowSetId("MainLog"..i, NewChatWindow.Messages[i].sourceId)
				WindowSetHandleInput("MainLog"..i, true)
			end
			
			
			
			
			local hueR, hueG, hueB
			if (type(NewChatWindow.Messages[i].color) == "number") then
				hueR, hueG, hueB = HueRGBAValue(NewChatWindow.Messages[i].color)
			else
				hueR = NewChatWindow.Messages[i].color.r
				hueG = NewChatWindow.Messages[i].color.g
				hueB = NewChatWindow.Messages[i].color.b
			end
			local text = NewChatWindow.Messages[i].text
			local prefix = L""
			local channel = NewChatWindow.Messages[i].channel
			if (NewChatWindow.Messages[i].ORGchannel) then
				channel = NewChatWindow.Messages[i].ORGchannel
			end
			
			if (channel == SystemData.ChatLogFilters.GUILD or channel == SystemData.ChatLogFilters.ALLIANCE or channel == SystemData.ChatLogFilters.PARTY ) and not NewChatWindow.hideTag then
						
				prefix = L"[" .. ChatSettings.Channels[channel].name .. L"]"
			end
			if (NewChatWindow.Messages[i].channel == SystemData.ChatLogFilters.SAY or NewChatWindow.Messages[i].channel == 16 ) then
				if ( NewChatWindow.Messages[i].sourceName and NewChatWindow.Messages[i].sourceName ~= L"" and NewChatWindow.Messages[i].sourceName ~= NewChatWindow.PlayerName) then
					if (NewChatWindow.Messages[i].channel == 16 ) then
						text = prefix.. NewChatWindow.Messages[i].sourceName .. L": " ..  NewChatWindow.Messages[i].text
					else
						text = prefix.. L"[" .. NewChatWindow.Messages[i].sourceName .. L"]: " .. NewChatWindow.Messages[i].text
					end
				end
				
				if (NewChatWindow.Messages[i].color == 0) then
					hueR= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].r
					hueG= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].g
					hueB= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].b
				end

				
			else
				if NewChatWindow.Messages[i].channel == SystemData.ChatLogFilters.SYSTEM and towstring(NewChatWindow.Messages[i].sourceName) ~= L"" then
					text = L"[" .. towstring(NewChatWindow.Messages[i].sourceName) .. L"]: " ..  NewChatWindow.Messages[i].text
					hueR= 255
					hueG= 0
					hueB= 0
				else
					if (NewChatWindow.Messages[i].channel ~= SystemData.ChatLogFilters.SYSTEM and NewChatWindow.Messages[i].channel ~= 15 and NewChatWindow.Messages[i].sourceName and NewChatWindow.Messages[i].sourceName ~= L"" ) then
						text = prefix.. L"[" .. NewChatWindow.Messages[i].sourceName .. L"]: " .. NewChatWindow.Messages[i].text
					end
					if (type(NewChatWindow.Messages[i].color) == "number") then
						hueR= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].r
						hueG= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].g
						hueB= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].b
					end
				end
			end
			if (NewChatWindow.TimeStamp) then
				text = L"[" .. NewChatWindow.Messages[i].timeStamp .. L"] " .. text
			end
			LabelSetText("MainLog"..i, text)
			LabelSetTextColor("MainLog"..i, hueR, hueG, hueB)
			local font = FontSelector.Fonts[NewChatWindow.ChannelsFonts[ NewChatWindow.Messages[i].channel ]].fontName .. "_" .. NewChatWindow.ChannelsFontsSize[ NewChatWindow.Messages[i].channel ]
			LabelSetFont("MainLog"..i,font , WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)

			if (i == 1 or NewChatWindow.Labels[0] < 1) then
				WindowAddAnchor("MainLog"..i, "topleft", "NewChatWindowJournalWindowScrollChildText", "topleft", 0, 0)
			else
				WindowAddAnchor("MainLog"..i, "bottomleft", "MainLog"..NewChatWindow.LastVis[0], "topleft", 0, 8)
			end

			NewChatWindow.Labels[0] = NewChatWindow.Labels[0] + 1
			NewChatWindow.LastMsg[0] = i + 1
			NewChatWindow.LastVis[0] = i
			local lblWidth, lblHeight = WindowGetDimensions("MainLog"..i)

		
			NewChatWindow.totalHeight[0] = NewChatWindow.totalHeight[0] + lblHeight + 8
			
			
		end
	end
	
	WindowSetDimensions("NewChatWindowJournalWindowScrollChildText", Width, NewChatWindow.totalHeight[0]  )
	ScrollWindowUpdateScrollRect( "NewChatWindowJournalWindow" )
	if (autoScroll and NewChatWindow.LastVis[0]) then
		WindowUtils.ScrollToElementInScrollWindow( "MainLog"..NewChatWindow.LastVis[0], "NewChatWindowJournalWindow", "NewChatWindowJournalWindowScrollChild" )
	end
	
	
	for j = 1, NewChatWindow.maxTabs do
		local templatename = "NewChatWindow" .. j
		if (DoesWindowNameExist(templatename)) then
			
			local autoScroll = true
	
			if (DoesWindowNameExist(templatename .. "Log" .. NewChatWindow.LastVis[j])) then
				local dontCare, maxOffset = WindowGetDimensions("NewChatWindowBookmark" .. j)
				local elementX,elementY = WindowGetScreenPosition(templatename .. "Log" .. NewChatWindow.LastVis[j])
				local parentX,parentY = WindowGetScreenPosition("NewChatWindowBookmark" .. j)
				local scrollOffset = elementY - parentY

				if( scrollOffset > maxOffset ) then
					autoScroll = false
				end
			end
						
			local Width, Height = WindowGetDimensions("NewChatWindowBookmark" .. j .. "ScrollChildText")

			WindowClearAnchors("NewChatWindowBookmark" .. j)	
			WindowAddAnchor("NewChatWindowBookmark" .. j, "topleft",templatename, "topleft", 5, 10 )
			WindowAddAnchor("NewChatWindowBookmark" .. j, "bottomright",templatename, "bottomright", -2, -10 )
			WindowSetLayer("NewChatWindowBookmark" .. j, Window.Layers.DEFAULT	)
			WindowSetParent("NewChatWindowBookmark" .. j, templatename)
			
			if (NewChatWindow.LastMsg[j]) then
				for i = NewChatWindow.LastMsg[j], table.getn(NewChatWindow.Messages) do
				
					if (not NewChatWindow.ChannelsEnabled[j][NewChatWindow.Messages[i].channel] or NewChatWindow.Messages[i].ignore) then
						continue
					end
					
					if(NewChatWindow.Messages[i].channel == 15) then
						local passa = NewChatWindow.SavedFilter[NewChatWindow.Messages[i].Notoriety+1]
						if (not NewChatWindow.SavedFilter[9] and MobilesOnScreen.IsFarm(NewChatWindow.Messages[i].sourceName)) then
								passa = false
						end
						if (not NewChatWindow.SavedFilter[10] and MobilesOnScreen.IsSummon(NewChatWindow.Messages[i].sourceName)) then
								passa = false
						end
						if not passa then
							continue
						end
					end
					if (NewChatWindow.Messages[i].channel == 16) then
						NewChatWindow.Messages[i].color = {r=192, g=192, b=248}
						NewChatWindow.Messages[i].sourceName = GetStringFromTid(3000610) -- Note to Self:
					end
					
					CreateWindowFromTemplate( templatename .. "Log"..i, "JournalItem", "NewChatWindowBookmark" .. j .. "ScrollChildText" )
					
					WindowSetParent(templatename .. "Log"..i, "NewChatWindowBookmark" .. j .. "ScrollChildText")
					
				
					WindowSetDimensions(templatename .. "Log"..i, Width - 15 , 20)
					if (NewChatWindow.Messages[i].channel == 15) then
						WindowSetId("Log"..i, NewChatWindow.Messages[i].sourceId)
						WindowSetHandleInput("Log"..i, true)
					end
					local hueR, hueG, hueB
					if (type(NewChatWindow.Messages[i].color) == "number") then
						hueR, hueG, hueB = HueRGBAValue(NewChatWindow.Messages[i].color)
					else
						hueR = NewChatWindow.Messages[i].color.r
						hueG = NewChatWindow.Messages[i].color.g
						hueB = NewChatWindow.Messages[i].color.b
					end
					local text = NewChatWindow.Messages[i].text
					local prefix = L""
					local channel = NewChatWindow.Messages[i].channel
					if (NewChatWindow.Messages[i].ORGchannel) then
						channel = NewChatWindow.Messages[i].ORGchannel
					end
					if (channel == SystemData.ChatLogFilters.GUILD or channel == SystemData.ChatLogFilters.ALLIANCE or channel == SystemData.ChatLogFilters.PARTY ) and not NewChatWindow.hideTag then
						
						prefix = L"[" .. ChatSettings.Channels[channel].name .. L"]"
					end
					if (NewChatWindow.Messages[i].channel == SystemData.ChatLogFilters.SAY or NewChatWindow.Messages[i].channel == 16 ) then
						if ( NewChatWindow.Messages[i].sourceName and NewChatWindow.Messages[i].sourceName ~= L"" and NewChatWindow.Messages[i].sourceName ~= NewChatWindow.PlayerName) then
							if (NewChatWindow.Messages[i].channel == 16 ) then
								text = prefix.. NewChatWindow.Messages[i].sourceName .. L" " .. NewChatWindow.Messages[i].text
							else
								text = prefix.. L"[" .. NewChatWindow.Messages[i].sourceName .. L"]: " .. NewChatWindow.Messages[i].text
							end
						end
						if (NewChatWindow.Messages[i].color == 0) then
							hueR= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].r
							hueG= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].g
							hueB= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].b
						end
						
						
					else
						if NewChatWindow.Messages[i].channel == SystemData.ChatLogFilters.SYSTEM and towstring(NewChatWindow.Messages[i].sourceName) ~= L"" then
							text = L"[" .. towstring(NewChatWindow.Messages[i].sourceName) .. L"]: " ..  NewChatWindow.Messages[i].text
							hueR= 255
							hueG= 0
							hueB= 0
						else
							if (NewChatWindow.Messages[i].channel ~= SystemData.ChatLogFilters.SYSTEM and NewChatWindow.Messages[i].channel ~= 15 and NewChatWindow.Messages[i].sourceName and NewChatWindow.Messages[i].sourceName ~= L"" ) then
								text = prefix.. L"[" .. NewChatWindow.Messages[i].sourceName .. L"]: " .. NewChatWindow.Messages[i].text
							end
							if (type(NewChatWindow.Messages[i].color) == "number") then
								hueR= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].r
								hueG= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].g
								hueB= ChatSettings.ChannelColors[NewChatWindow.Messages[i].channel].b
							end
						end
					end
					if (NewChatWindow.TimeStamp) then
						text = L"[" .. NewChatWindow.Messages[i].timeStamp .. L"] " .. text
					end
					LabelSetText(templatename .. "Log"..i, text)
					LabelSetTextColor(templatename .. "Log"..i, hueR, hueG, hueB)
					local font = FontSelector.Fonts[NewChatWindow.ChannelsFonts[ NewChatWindow.Messages[i].channel ]].fontName .. "_" .. NewChatWindow.ChannelsFontsSize[ NewChatWindow.Messages[i].channel ]
					LabelSetFont(templatename .. "Log"..i,font , WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)

					if (i == 1 or NewChatWindow.Labels[j] < 1) then
						WindowAddAnchor(templatename .. "Log"..i, "topleft", "NewChatWindowBookmark" .. j .. "ScrollChildText", "topleft", 0, 0)
					else
						WindowAddAnchor(templatename .. "Log"..i, "bottomleft", templatename .. "Log"..NewChatWindow.LastVis[j], "topleft", 0, 8)
					end

					NewChatWindow.Labels[j] = NewChatWindow.Labels[j] + 1
					NewChatWindow.LastMsg[j] = i + 1
					NewChatWindow.LastVis[j] = i
					local lblWidth, lblHeight = WindowGetDimensions(templatename .. "Log"..i)

				
					NewChatWindow.totalHeight[j] = NewChatWindow.totalHeight[j] + lblHeight + 8
					
				end
			end
			WindowSetDimensions("NewChatWindowBookmark" .. j .. "ScrollChildText", Width, NewChatWindow.totalHeight[j]  )
			ScrollWindowUpdateScrollRect( "NewChatWindowBookmark" .. j )
			if (autoScroll and NewChatWindow.LastVis[j]) then
				WindowUtils.ScrollToElementInScrollWindow( templatename .. "Log" .. NewChatWindow.LastVis[j], "NewChatWindowBookmark" .. j, "NewChatWindowBookmark" .. j .. "ScrollChild" )
			end
			WindowAssignFocus("NewChatWindowBookmark" .. j, false)
		end
	
	end
	local totalVis = 0
	if (NewChatWindow.Labels[i]) then
		for i = 0, NewChatWindow.maxTabs do
			totalVis = totalVis + (NewChatWindow.Labels[i] - NewChatWindow.PrevLabels[i])
		end
	end
	if (totalVis > 0) then
		
		if ((NewChatWindow.Labels[0] - NewChatWindow.PrevLabels[0]) > 0) then
			NewChatWindow.PrevLabels[0] = NewChatWindow.Labels[0]
			WindowStopAlphaAnimation("NewChatWindow")
			WindowStopAlphaAnimation("NewChatWindowJournalWindowScrollbar")
			WindowStopAlphaAnimation("NewChatWindowJournalWindow")
			if (DoesWindowNameExist("Bookmark1")) then
				WindowStopAlphaAnimation("Bookmark1")
				WindowSetAlpha("Bookmark1", NewChatWindow.BaseAlpha)
			end
			WindowSetAlpha("NewChatWindowJournalWindow", 1)
			WindowSetAlpha("NewChatWindow", NewChatWindow.BaseAlpha)
			WindowSetAlpha("NewChatWindowJournalWindowScrollbar",2)
			WindowSetLayer("NewChatWindowJournalWindow", Window.Layers.DEFAULT	)	
			WindowSetParent("NewChatWindowJournalWindow", "NewChatWindow")
			
			for i = 1, table.getn(NewChatWindow.Messages) do
				if (DoesWindowNameExist("MainLog"..i)) then
					WindowSetAlpha("MainLog"..i, 2)
					WindowSetFontAlpha("MainLog"..i, 2)
				end
			end
			
		end
		
		for j = 1, NewChatWindow.maxTabs do
			local templatename = "NewChatWindow" .. j
			
			
			if (DoesWindowNameExist(templatename) and (NewChatWindow.Labels[j] - NewChatWindow.PrevLabels[j]) > 0 ) then
				if (DoesWindowNameExist("Bookmark" .. j+1)) then
					WindowStopAlphaAnimation("Bookmark" .. j+1)
					WindowSetAlpha("Bookmark" .. j+1, NewChatWindow.BaseAlpha)
				end
				
				NewChatWindow.PrevLabels[j] = NewChatWindow.Labels[j]
				WindowStopAlphaAnimation(templatename)
				WindowStopAlphaAnimation("NewChatWindowBookmark" .. j .. "Scrollbar")
				WindowStopAlphaAnimation("NewChatWindowBookmark" .. j)
				
				WindowSetLayer("NewChatWindowBookmark" .. j, Window.Layers.DEFAULT	)
				WindowSetParent("NewChatWindowBookmark" .. j, templatename)
				
				WindowSetAlpha("NewChatWindowBookmark" .. j, 1)
				WindowSetAlpha(templatename, NewChatWindow.BaseAlpha)
				WindowSetAlpha("NewChatWindowBookmark" .. j .. "Scrollbar", 2)
				for i = 1, table.getn(NewChatWindow.Messages) do
					if (DoesWindowNameExist( templatename .. "Log" ..i)) then
						WindowSetAlpha( templatename .. "Log" ..i, 2)
						WindowSetFontAlpha( templatename .. "Log" ..i, 2)
					end
				end
			end
		end
		NewChatWindow.OnMouseOverEnd()
		
		NewChatWindow.delta = 0
		
		NewChatWindow.hidden = false
	end

end

function NewChatWindow.ShowAgain(bypass)

	if (NewChatWindow.showMouseOver or bypass == true) then
		WindowStopAlphaAnimation("NewChatWindow")
		WindowStopAlphaAnimation("NewChatWindowJournalWindowScrollbar")
		WindowStopAlphaAnimation("NewChatWindowJournalWindow")
		
		WindowSetAlpha("NewChatWindowJournalWindow", 1)
		WindowSetAlpha("NewChatWindow", NewChatWindow.BaseAlpha)
		WindowSetAlpha("NewChatWindowJournalWindowScrollbar", 2)
		WindowSetParent("NewChatWindowJournalWindow", "NewChatWindow")
		WindowSetLayer("NewChatWindowJournalWindow", Window.Layers.DEFAULT	)
		for i = 1, table.getn(NewChatWindow.Messages) do
			if (DoesWindowNameExist("MainLog"..i)) then
				WindowSetAlpha("MainLog"..i, 2)
				WindowSetFontAlpha("MainLog"..i, 2)
			end
		end
		for j = 1, NewChatWindow.maxTabs do
			local templatename = "NewChatWindow" .. j
			if (DoesWindowNameExist("Bookmark" .. j)) then
				WindowStopAlphaAnimation("Bookmark" .. j)
				WindowSetAlpha("Bookmark" .. j, NewChatWindow.BaseAlpha)
			end
			if (DoesWindowNameExist( templatename)) then
				WindowStopAlphaAnimation(templatename)
				WindowStopAlphaAnimation("NewChatWindowBookmark" .. j .. "Scrollbar")
				WindowStopAlphaAnimation("NewChatWindowJournalWindow")
				
				WindowSetAlpha("NewChatWindowBookmark" .. j, 1)
				WindowSetAlpha(templatename, NewChatWindow.BaseAlpha)
				WindowSetAlpha("NewChatWindowBookmark" .. j .. "Scrollbar", 2)
				
				WindowSetParent("NewChatWindowBookmark" .. j, templatename)
				WindowSetLayer("NewChatWindowBookmark" .. j, Window.Layers.DEFAULT	)
				for i = 1, table.getn(NewChatWindow.Messages) do
					if (DoesWindowNameExist( templatename .. "Log" ..i)) then
						WindowSetAlpha( templatename .. "Log" ..i, 2)
						WindowSetFontAlpha( templatename .. "Log" ..i, 2)
					end
				end
			end
		end
		
		NewChatWindow.delta = 0
		
		NewChatWindow.hidden = false
		NewChatWindow.OnMouseOverEnd()
	end
end


function NewChatWindow.Rubber()
	NewChatWindow.ClearAll()
	for i = 0, NewChatWindow.maxTabs do
		NewChatWindow.LastMsg[i] = 1
		NewChatWindow.LastVis[i] = 1
		NewChatWindow.totalHeight[i] = 0
		NewChatWindow.Labels[i] = 0
		NewChatWindow.PrevLabels[i] = 0
	end
	NewChatWindow.Messages = {}
end 


function NewChatWindow.RubberToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,GetStringFromTid(1155212) )
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end


function NewChatWindow.Font()
	for i = 1, table.getn(ChatSettings.Channels) do
		ContextMenu.CreateLuaContextMenuItemWithString(ChatSettings.Channels[i].name,0,i,1,false)
	end
	ContextMenu.CreateLuaContextMenuItemWithString(ChatSettings.Channels[SystemData.ChatLogFilters.GM].name,0,SystemData.ChatLogFilters.GM,1,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155206),0,14,1,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155208),0,15,1,false)
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155209),0,16,1,false)
	
	ContextMenu.ActivateLuaContextMenu(NewChatWindow.FontContextMenuCallback)
		
end 

function NewChatWindow.FontContextMenuCallback( returnCode, param )

		FontSelector.Selection = "journal" .. returnCode
		if (not DoesWindowNameExist("FontSelector")) then
			CreateWindow("FontSelector", true)
		else
			WindowSetShowing("FontSelector", true)
		end
		FontSelector.OnShown()
		
		WindowSetShowing(FontSelector.RunicFontItem, false)
		WindowUtils.SetWindowTitle("FontSelector", L"Overhead Chat Font")
 

end 

function NewChatWindow.FontToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,L"Set Fonts" )
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function NewChatWindow.FontSize()
	for i = 1, table.getn(ChatSettings.Channels) do
		ContextMenu.CreateLuaContextMenuItemWithString(ChatSettings.Channels[i].name .. L" (" .. NewChatWindow.ChannelsFontsSize[ i ] .. L")",0,i,1,false)
	end


	ContextMenu.CreateLuaContextMenuItemWithString(ChatSettings.Channels[SystemData.ChatLogFilters.GM].name .. L" (" .. NewChatWindow.ChannelsFontsSize[ SystemData.ChatLogFilters.GM ] .. L")",0,SystemData.ChatLogFilters.GM,1,false)
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155206) .. L" (" .. NewChatWindow.ChannelsFontsSize[ 14 ] .. L")",0,14,1,false)
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155208) .. L" (" .. NewChatWindow.ChannelsFontsSize[ 15 ] .. L")",0,15,1,false)
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1155209) .. L" (" .. NewChatWindow.ChannelsFontsSize[ 16 ] .. L")",0,16,1,false)
		
	ContextMenu.ActivateLuaContextMenu(NewChatWindow.FontSizeContextMenuCallback)
end 

function NewChatWindow.FontSizeContextMenuCallback( returnCode, param )

	local rdata = {title=GetStringFromTid(1155213), subtitle=GetStringFromTid(1155214), callfunction=NewChatWindow.SetFontSize, id=returnCode}
	RenameWindow.Create(rdata)
end

function NewChatWindow.SetFontSize(id, px)

	id = tonumber(id)
	if (type(tonumber(px)) == "number") then
		px = tonumber(px)
	else
		px = 12
	end
	if px > 36 then
		px = 36
	end
	if px < 8 then
		px = 8
	end
	
	NewChatWindow.ChannelsFontsSize[ id ]  = px
	Interface.SaveNumber( "ChannelsFontsSize" .. id,NewChatWindow.ChannelsFontsSize[ id ] ) 
	NewChatWindow.ClearAll()
	NewChatWindow.UpdateLog()
end

function NewChatWindow.FontSizeToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,GetStringFromTid(1155213) )
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end


function NewChatWindow.FontColor()
	WindowSetShowing( "NewChatOptionsWindow", true)
end 
function NewChatWindow.FontColorToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,GetStringFromTid(1155215) )
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function NewChatWindow.ChatSettingsToolTip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,GetStringFromTid(1155216) )
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function NewChatWindow.UpdateSettings()
	SliderBarSetCurrentPosition("BaseAlphaSliderBar", NewChatWindow.BaseAlpha )
	LabelSetText( "BaseAlphaVal", L"" .. NewChatWindow.BaseAlpha)
	SliderBarSetCurrentPosition("FadeDelaySliderBar", NewChatWindow.waitTime / 20 )
	LabelSetText( "FadeDelayVal", L"" .. NewChatWindow.waitTime)
	SliderBarSetCurrentPosition("MinTotDamageSliderBar", NewChatWindow.minTotDmg / 1000 )
	LabelSetText( "MinTotDamageVal", L"" .. NewChatWindow.minTotDmg)
	
	ButtonSetPressedFlag("AutoHideCheckButton", NewChatWindow.autoHide)
	ButtonSetPressedFlag("ShowMouseOverButton", NewChatWindow.showMouseOver)
	ButtonSetPressedFlag("FadeTextButton", NewChatWindow.TextFade)
	ButtonSetPressedFlag("TimeStampButton", NewChatWindow.TimeStamp)
	ButtonSetPressedFlag("LockWindowButton", NewChatWindow.Locked)
	
	for i = 2, table.getn(NewChatWindow.Filter) do
		local templatename = "YouSeeFilterCheckButton_"..i
		ButtonSetPressedFlag(templatename.."Button", NewChatWindow.SavedFilter[i])
	end
	
	ButtonSetPressedFlag("SpellsButton", NewChatWindow.ShowSpells)
	ButtonSetPressedFlag("SpellsCastingButton", NewChatWindow.ShowSpellsCasting)
	ButtonSetPressedFlag("PerfectionMsgsButton", NewChatWindow.ShowPerfection)
	ButtonSetPressedFlag("PreventsMultipleButton", NewChatWindow.ShowMultiple)
	ButtonSetPressedFlag("HideTagsButton", NewChatWindow.hideTag)
	
end

function NewChatWindow.OnSettingsHidden()
	local needReload = false
	
	local barVal = SliderBarGetCurrentPosition("BaseAlphaSliderBar" )
	barVal = tonumber(string.format("%.2f", barVal))
	if (barVal < 0.01) then
		barVal = 0.01
		SliderBarSetCurrentPosition("BaseAlphaSliderBar", barVal )
	end
	NewChatWindow.BaseAlpha = barVal
	Interface.SaveNumber( "NewChatWindowBaseAlpha",barVal )
	
	
	barVal =  tonumber(string.format("%.0f", SliderBarGetCurrentPosition("FadeDelaySliderBar" ) * 20))
	if (barVal < 1) then
		barVal = 1
		SliderBarSetCurrentPosition("FadeDelaySliderBar", barVal / 20 )
	end
	NewChatWindow.waitTime = barVal
	Interface.SaveNumber( "NewChatWindowwaitTime",NewChatWindow.waitTime )
	
	
	barVal =  tonumber(string.format("%.0f", SliderBarGetCurrentPosition("MinTotDamageSliderBar" ) * 1000))
	if (barVal < 1) then
		barVal = 1
		SliderBarSetCurrentPosition("MinTotDamageSliderBar", barVal / 1000 )
	end
		
	NewChatWindow.minTotDmg = barVal
	Interface.SaveNumber( "NewChatWindowminTotDmg",NewChatWindow.minTotDmg )
		
		
		
	WindowSetAlpha("NewChatWindow", NewChatWindow.BaseAlpha)
	WindowSetAlpha("NewChatWindowJournalWindowScrollbar", 2)
	for j = 1, NewChatWindow.maxTabs do
		local templatename = "NewChatWindow" .. j
		if (DoesWindowNameExist(templatename)) then
			WindowSetAlpha(templatename, NewChatWindow.BaseAlpha)
			WindowSetAlpha("NewChatWindowBookmark" .. j .. "Scrollbar", 2)
		end
	end

	NewChatWindow.autoHide = ButtonGetPressedFlag("AutoHideCheckButton")
	Interface.SaveBoolean( "NewChatWindowAutoHide", NewChatWindow.autoHide ) 
	
	NewChatWindow.showMouseOver = ButtonGetPressedFlag("ShowMouseOverButton")
	Interface.SaveBoolean( "NewChatWindowshowMouseOver", NewChatWindow.showMouseOver ) 
	
	NewChatWindow.TextFade = ButtonGetPressedFlag("FadeTextButton")
	Interface.SaveBoolean( "NewChatWindowTextFade", NewChatWindow.TextFade )
	
	NewChatWindow.TimeStamp = ButtonGetPressedFlag("TimeStampButton")
	Interface.SaveBoolean( "NewChatWindowTimeStamp", NewChatWindow.TimeStamp )
	
	NewChatWindow.Locked = ButtonGetPressedFlag("LockWindowButton")
	Interface.SaveBoolean( "NewChatWindowLocked", NewChatWindow.Locked ) 
	 for j = 1, NewChatWindow.maxTabs do
		local templatename = "NewChatWindow" .. j .."ResizeButton"
		if (DoesWindowNameExist( templatename)) then
			WindowSetShowing(templatename, not NewChatWindow.Locked)
		end
	end
	
	for i = 2, table.getn(NewChatWindow.Filter) do
		NewChatWindow.SavedFilter[i] = ButtonGetPressedFlag("YouSeeFilterCheckButton_"..i.."Button") 
		Interface.SaveBoolean( "NewChatYSFilter"..i, NewChatWindow.SavedFilter[i] )
	end
	
	NewChatWindow.ShowSpells = ButtonGetPressedFlag("SpellsButton")
	Interface.SaveBoolean( "NewChatWindowShowSpells", NewChatWindow.ShowSpells )
	
	NewChatWindow.ShowSpellsCasting = ButtonGetPressedFlag("SpellsCastingButton")
	Interface.SaveBoolean( "NewChatWindowShowSpellsCasting", NewChatWindow.ShowSpellsCasting )
	
	NewChatWindow.ShowPerfection = ButtonGetPressedFlag("PerfectionMsgsButton")
	Interface.SaveBoolean( "NewChatWindowShowPerfection", NewChatWindow.ShowPerfection )
	
	NewChatWindow.ShowMultiple = ButtonGetPressedFlag("PreventsMultipleButton")
	Interface.SaveBoolean( "NewChatWindowShowMultiple", NewChatWindow.ShowMultiple )
	
	NewChatWindow.hideTag = ButtonGetPressedFlag("HideTagsButton")
	Interface.SaveBoolean( "NewChatWindowhideTag", NewChatWindow.hideTag )
	
	Interface.LockChatLine = ButtonGetPressedFlag("LockLineButton")
	Interface.SaveBoolean( "LockChatLine", Interface.LockChatLine )
	
	
	NewChatWindow.ClearAll()
	NewChatWindow.UpdateLog()
	WindowSetShowing("NewChatWindowResizeButton", not NewChatWindow.Locked)
	NewChatWindow.ShowAgain(true)
	
	

	
	
	return needReload
end 

NewChatWindow.over = ""

function NewChatWindow.BookmarkToolTip()
	for i = 1, NewChatWindow.TabCount do
		if (DoesWindowNameExist("Bookmark" .. i .. "Text")) then
			if (i == NewChatWindow.ActiveTab) then
				local extTabs = 0
				for j = 1, NewChatWindow.maxTabs do
					local templatename = "NewChatWindow" .. j .."ResizeButton"
					if (DoesWindowNameExist( templatename)) then
						WindowSetShowing(templatename, not NewChatWindow.Locked)
						if (NewChatWindow.TabStatus[j].extracted) then
							extTabs = extTabs +1
						end
					end
				end
				if (NewChatWindow.TabCount - extTabs > 1) then
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.ActiveColor.r, NewChatWindow.ActiveColor.g, NewChatWindow.ActiveColor.b)
				else
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
				end
			else
				LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
			end
		end
	end
	if (string.find(SystemData.ActiveWindow.name, "Text")) then
		LabelSetTextColor(SystemData.ActiveWindow.name, NewChatWindow.HighlightColor.r, NewChatWindow.HighlightColor.g, NewChatWindow.HighlightColor.b)
		NewChatWindow.over  = SystemData.ActiveWindow.name
	elseif (string.find(SystemData.ActiveWindow.name, "IMG")) then
		LabelSetTextColor(string.gsub(SystemData.ActiveWindow.name,"IMG", "") .. "Text", NewChatWindow.HighlightColor.r, NewChatWindow.HighlightColor.g, NewChatWindow.HighlightColor.b)
		NewChatWindow.over  = string.gsub(NewChatWindow.over,"IMG", "")
	else
		LabelSetTextColor(SystemData.ActiveWindow.name .. "Text", NewChatWindow.HighlightColor.r, NewChatWindow.HighlightColor.g, NewChatWindow.HighlightColor.b)
		NewChatWindow.over  = SystemData.ActiveWindow.name .. "Text"
	end
	
end

function NewChatWindow.OnMouseOverEnd()
	for i = 1, NewChatWindow.TabCount do
		if (DoesWindowNameExist("Bookmark" .. i .. "Text")) then
			WindowSetAlpha("Bookmark" .. i .. "Text", 2)
			WindowSetFontAlpha("Bookmark" .. i .. "Text", 2)
			if (i == NewChatWindow.ActiveTab) then
				local extTabs = 0
				for j = 1, NewChatWindow.maxTabs do
					local templatename = "NewChatWindow" .. j .."ResizeButton"
					if (DoesWindowNameExist( templatename)) then
						WindowSetShowing(templatename, not NewChatWindow.Locked)
						if (NewChatWindow.TabStatus[j].extracted) then
							extTabs = extTabs +1
						end
					end
				end
				if (NewChatWindow.TabCount - extTabs > 1) then
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.ActiveColor.r, NewChatWindow.ActiveColor.g, NewChatWindow.ActiveColor.b)
				else
					LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
				end
			else
				LabelSetTextColor("Bookmark" .. i .. "Text", NewChatWindow.NormalColor.r, NewChatWindow.NormalColor.g, NewChatWindow.NormalColor.b)
			end
		end
	end
end

function NewChatWindow.OnLButtonDown()
	if (not NewChatWindow.Locked ) then
		WindowSetMoving(WindowUtils.GetActiveDialog(),true)
		SnapUtils.StartWindowSnap(WindowUtils.GetActiveDialog())
		NewChatWindow.waithide = true
	else
		WindowSetMoving(WindowUtils.GetActiveDialog(),false)
	end
end

function NewChatWindow.OnLButtonDownJW()
	local id = WindowGetId(WindowUtils.GetActiveDialog())
	if (id == 0) then
		id = ""
	end
	if (not NewChatWindow.Locked ) then
		WindowSetMoving("NewChatWindow" .. id,true)
		SnapUtils.StartWindowSnap("NewChatWindow" .. id)
		NewChatWindow.waithide = true
	else
		WindowSetMoving("NewChatWindow" .. id,false)
	end
end

function NewChatWindow.OnLButtonUpJW()
	local id = WindowGetId(WindowUtils.GetActiveDialog())
	if (id == 0) then
		id = ""
	end
	WindowSetMoving("NewChatWindow" .. id,false)
	NewChatWindow.waithide = false
end

function NewChatWindow.OnLButtonUp()
	WindowSetMoving(WindowUtils.GetActiveDialog(),false)
	NewChatWindow.waithide = false
end

function NewChatWindow.OnUpdate(timePassed)
	NewChatWindow.deltaUpd = NewChatWindow.deltaUpd + timePassed
	if (NewChatWindow.deltaUpd > NewChatWindow.MinUpdateRate) then
		
		NewChatWindow.blockUpdate = false
		NewChatWindow.deltaUpd = 0
		if (NewChatWindow.UpdateReq) then
			NewChatWindow.UpdateLog()
			NewChatWindow.UpdateReq = false
		end
	end
	
	
	if (NewChatWindow.autoHide and not NewChatWindow.waithide) then
		NewChatWindow.delta = NewChatWindow.delta + timePassed
		if (NewChatWindow.delta >= NewChatWindow.waitTime and not NewChatWindow.hidden) then
			if (WindowGetAlpha("NewChatWindow") > 0.01) then
				WindowStartAlphaAnimation("NewChatWindow", Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.01, 2, false, 0, 1 )
				if (DoesWindowNameExist("Bookmark1") and WindowGetAlpha("Bookmark1") > 0.01) then
					WindowStartAlphaAnimation("Bookmark1", Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.01, 2, false, 0, 1 )
				end
				if (not NewChatWindow.TextFade) then
					WindowSetParent("NewChatWindowJournalWindow", "Root")
					WindowSetLayer("NewChatWindowJournalWindow", Window.Layers.BACKGROUND	)
					WindowStartAlphaAnimation("NewChatWindowJournalWindowScrollbar", Window.AnimationType.SINGLE_NO_RESET, 1, 0.01, 2, false, 0, 1 )
				else
					WindowStartAlphaAnimation("NewChatWindowJournalWindow", Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.01, 2, false, 0, 1 )
				end
			end
			for j = 1, NewChatWindow.maxTabs do
				local templatename = "NewChatWindow" .. j
				if (DoesWindowNameExist("Bookmark" .. j+1)) then
					WindowStartAlphaAnimation("Bookmark" .. j+1, Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.01, 2, false, 0, 1 )
				end
				if (DoesWindowNameExist( templatename) and WindowGetAlpha(templatename) > 0.01) then
					WindowStartAlphaAnimation(templatename, Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.01, 2, false, 0, 1 )
					if (not NewChatWindow.TextFade) then
						WindowSetParent("NewChatWindowBookmark" .. j, "Root")
						WindowSetLayer("NewChatWindowBookmark" .. j, Window.Layers.BACKGROUND	)
						WindowStartAlphaAnimation("NewChatWindowBookmark" .. j .. "Scrollbar", Window.AnimationType.SINGLE_NO_RESET, 1, 0.01, 2, false, 0, 1 )
					else
						WindowStartAlphaAnimation("NewChatWindowBookmark" .. j, Window.AnimationType.SINGLE_NO_RESET, NewChatWindow.BaseAlpha, 0.1, 2, false, 0, 1 )
					end
				end
			end
			
			NewChatWindow.hidden = true			
		end
	end
end 