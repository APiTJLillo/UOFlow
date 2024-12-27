----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ChatFiltersWindow = {}

ChatFiltersWindow.TID = { ChatFilters=1111674,Accept=1013076 }

ChatFiltersWindow.channelListData = {}
ChatFiltersWindow.channelListOrder = {}
ChatFiltersWindow.channelFiltersState = {}

local wndIndex = 0
local function InitChatOptionListData()
    ChatFiltersWindow.channelListData = {}
    local channelIndex = 0
    for channel, channelData in pairs(ChatSettings.Channels) do
        if (channelData ~= nil and channelData.name ~= nil and channelData.isOnAlways == false) then
            channelIndex = channelIndex + 1
            ChatFiltersWindow.channelListData[channelIndex] = {}
            ChatFiltersWindow.channelListData[channelIndex].channelName = channelData.name
            ChatFiltersWindow.channelListData[channelIndex].color = ChatSettings.ChannelColors[channel]
            ChatFiltersWindow.channelListData[channelIndex].logName = channelData.logName
            ChatFiltersWindow.channelListData[channelIndex].channelID = channelData.id
        end
    end
end

local function FilterChannelList()

    -- Reset the tables
    ChatFiltersWindow.channelListOrder = {}
    ChatFiltersWindow.channelFiltersState = {}
    
    local active
    wndIndex = ChatWindow.activeWindow
    for idx, info in ipairs (ChatSettings.Ordering) do
        
        for dataIndex, data in ipairs( ChatFiltersWindow.channelListData ) do
            if (info == data.channelID)
            then
                table.insert(ChatFiltersWindow.channelListOrder, dataIndex)
                active = LogDisplayGetFilterState( ChatWindow.Windows[wndIndex].Tabs[1].tabWindow, data.logName, data.channelID)
                -- Cache off all of the values, for comparison later
                ChatFiltersWindow.channelFiltersState[idx] = active
                if (idx < ChatFiltersWindowList.numVisibleRows)
                then
                    -- Only fill the table with the number of Checkboxes actually visible
                    ButtonSetPressedFlag("ChatFiltersWindowListRow"..idx.."CheckBox", active)
                end
                break
            end
        end
    end
end

local function ResetChannelList()
    -- Filter, Sort, and Update
    InitChatOptionListData()
    FilterChannelList()
    ListBoxSetDisplayOrder( "ChatFiltersWindowList", ChatFiltersWindow.channelListOrder )
end

-- OnInitialize Handler
function ChatFiltersWindow.Initialize()
    WindowUtils.SetWindowTitle("ChatFiltersWindow", GetStringFromTid(ChatFiltersWindow.TID.ChatFilters) )
    ButtonSetText( "ChatFiltersWindowAcceptButton", GetStringFromTid(ChatFiltersWindow.TID.Accept) ) 
    
    -- This window starts invisible
    ChatFiltersWindow.Hide()
end

function ChatFiltersWindow.Hide()
    WindowSetShowing( "ChatFiltersWindow", false )
end

function ChatFiltersWindow.OnShown()
    if( ChatWindow.activeWindow ~= nil ) then
        ResetChannelList()
        ChatFiltersWindow.UpdateChatOptionRow()
    else
        ChatFiltersWindow.Hide()
    end
end

function ChatFiltersWindow.OnHidden()
end

function ChatFiltersWindow.Shutdown()
end

function ChatFiltersWindow.SetDefaultFilters()
    local chatTab = ChatWindow.Windows[1].Tabs[1]
    local journalTab = ChatWindow.Windows[2].Tabs[1]

    for channel, channelData in pairs(ChatSettings.Channels) do
        if (channelData.logName == "Chat")
        then       
            -- Filter all of the defaults for Chat
            LogDisplaySetFilterState( chatTab.tabWindow, channelData.logName, channelData.channelID, (channelData.isOnAlways or channelData.isOnChat) )
            LogDisplaySetFilterState( journalTab.tabWindow, channelData.logName, channelData.channelID, (channelData.isOnAlways or channelData.isOnJournal) )
        else
            Debug.Print("Invalid Log Name for Chat Filter")
        end
    end
    
    
end

function ChatFiltersWindow.TabChanged()
    
end

-- Callback from the <List> that updates a single row.
function ChatFiltersWindow.UpdateChatOptionRow()
    if (ChatFiltersWindowList.PopulatorIndices ~= nil) then
        local active = false
        local labelName
        local tab = ChatWindow.GetMenuTab()
        for rowIndex, dataIndex in ipairs(ChatFiltersWindowList.PopulatorIndices) do
            labelName = "ChatFiltersWindowListRow"..rowIndex.."ChannelName"
            LabelSetTextColor(labelName, 
                              ChatFiltersWindow.channelListData[dataIndex].color.r, 
                              ChatFiltersWindow.channelListData[dataIndex].color.g,
                              ChatFiltersWindow.channelListData[dataIndex].color.b)
            local actualIndex = 0
    
            for idx=1, #ChatSettings.Ordering do
                if (ChatFiltersWindow.channelListData[dataIndex].channelID == ChatSettings.Ordering[idx])
                then
                    actualIndex = idx
                end
            end
            if (actualIndex ~= 0)
            then
                active = ChatFiltersWindow.channelFiltersState[actualIndex]
            end
            ButtonSetPressedFlag("ChatFiltersWindowListRow"..rowIndex.."CheckBox", active)
        end
    end
end
function ChatFiltersWindow.SetAllFiltersChanges()
    local active = false
    local activeTab = ChatWindow.Windows[wndIndex].Tabs[1]
    for idx=1, #ChatSettings.Ordering do
        
        active = LogDisplayGetFilterState( activeTab.tabWindow, 
                        ChatSettings.Channels[ChatSettings.Ordering[idx]].logName, ChatSettings.Ordering[idx])
        if (active ~= ChatFiltersWindow.channelFiltersState[idx])
        then
            -- This item has changed, update the filter now
            LogDisplaySetFilterState( activeTab.tabWindow, ChatSettings.Channels[ChatSettings.Ordering[idx]].logName,  
                        ChatSettings.Ordering[idx], ChatFiltersWindow.channelFiltersState[idx])
        end
    end
    ChatFiltersWindow.Hide()
end
function ChatFiltersWindow.OnToggleChannel()
    local windowIndex = WindowGetId (SystemData.ActiveWindow.name)
    local windowParent = WindowGetParent (SystemData.ActiveWindow.name)
    local dataIndex = ListBoxGetDataIndex (windowParent, windowIndex)
    local actualIndex = 0
    
    -- Search for the index of the Channel we're altering
    for idx=1, #ChatSettings.Ordering do
        if (ChatFiltersWindow.channelListData[dataIndex].channelID == ChatSettings.Ordering[idx])
        then
            actualIndex = idx
        end
    end
    
    -- Toggle the channel
    if (ChatFiltersWindow.channelFiltersState[actualIndex] == true)
    then
        ChatFiltersWindow.channelFiltersState[actualIndex] = false
    else
        ChatFiltersWindow.channelFiltersState[actualIndex] = true
    end
    
    -- Update the button
    local channelCheckBox = "ChatFiltersWindowListRow"..windowIndex.."CheckBox"
    ButtonSetPressedFlag(channelCheckBox, ChatFiltersWindow.channelFiltersState[actualIndex])
end

