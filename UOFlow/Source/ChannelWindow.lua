----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ChannelWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

ChannelWindow.currentSelection = -1

ChannelWindow.TID = {
	Title = 1114073,
	YourCurrentChannel = 1114072,
	Join = 1114074,
	Leave = 1114075,
	Create = 1114076,
	Okay = 3000093,
	Cancel = 1006045,
	CreateChannelTitle = 1114077
}

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function ChannelWindow.Initialize()
	Interface.DestroyWindowOnClose["ChannelWindow"] = true
	
	WindowUtils.SetWindowTitle("ChannelWindow", GetStringFromTid(ChannelWindow.TID.Title))
	
	LabelSetText("ChannelWindowCurrentChannelDescLabel", GetStringFromTid(ChannelWindow.TID.YourCurrentChannel))
	
	ButtonSetText( "ChannelWindowJoinButton", GetStringFromTid(ChannelWindow.TID.Join) )
	ButtonSetText( "ChannelWindowLeaveButton", GetStringFromTid(ChannelWindow.TID.Leave) )
	ButtonSetText( "ChannelWindowCreateButton", GetStringFromTid(ChannelWindow.TID.Create) )
	
	ChannelWindow.UpdateCurrentChannel()
	
	local previousChannelButton = nil
	local currentChannelButton = nil
	
	for i = 1, WindowData.ChannelListCount do
		currentChannelButton = "channel_"..tostring(i)
		
		CreateWindowFromTemplate(currentChannelButton, "ChannelButtonTemplate", "ChannelListChildWindow")
		ButtonSetText(currentChannelButton, WindowData.ChannelList[i])
		ButtonSetPressedFlag(currentChannelButton, false)
		WindowSetId(currentChannelButton, i)
		
		if (previousChannelButton == nil) then
			WindowAddAnchor(currentChannelButton, "topleft", "ChannelListChildWindow", "topleft", 10, 5)
			ButtonSetPressedFlag(currentChannelButton, true)
			ChannelWindow.currentSelection = i
		else
			WindowAddAnchor(currentChannelButton, "bottomleft", previousChannelButton, "topleft", 0, 0)
		end
		previousChannelButton = currentChannelButton
	end
	
	WindowRegisterEventHandler( "ChannelWindow", SystemData.Events.CURRENT_CHANNEL_UPDATED, "ChannelWindow.UpdateCurrentChannel" )
	WindowUtils.RestoreWindowPosition("ChannelWindow",false)
end


function ChannelWindow.Shutdown()
	WindowUtils.SaveWindowPosition("ChannelWindow")
end

function ChannelWindow.CreateWindowInitialize()
	Interface.DestroyWindowOnClose["CreateChannelWindow"] = true
	
	WindowUtils.SetWindowTitle("CreateChannelWindow", GetStringFromTid(ChannelWindow.TID.CreateChannelTitle))
	ButtonSetText( "CreateChannelWindowOkayButton", GetStringFromTid(ChannelWindow.TID.Okay) )
	ButtonSetText( "CreateChannelWindowCancelButton", GetStringFromTid(ChannelWindow.TID.Cancel) )
	
end

function ChannelWindow.ToggleChannel()
	local previousSelection = ChannelWindow.currentSelection

	ChannelWindow.currentSelection = WindowGetId(SystemData.ActiveWindow.name)
	
	if(previousSelection and previousSelection ~= -1) then
		ButtonSetPressedFlag("channel_"..tostring(previousSelection), false)
	end
	ButtonSetPressedFlag("channel_"..tostring(ChannelWindow.currentSelection), true)
	ScrollWindowUpdateScrollRect("ChannelListWindow")
end

function ChannelWindow.UpdateCurrentChannel()
	if(WindowData.CurrentChannel == L"") then
		LabelSetText("ChannelWindowCurrentChannelLabel", GetStringFromTid(1011051))
		LabelSetTextColor( "ChannelWindowCurrentChannelLabel", 175, 175, 175 )
	else
		LabelSetText("ChannelWindowCurrentChannelLabel", WindowData.CurrentChannel)
		LabelSetTextColor( "ChannelWindowCurrentChannelLabel", 255, 255, 255 )
	end
end

function ChannelWindow.Join_OnLButtonUp()
	local windowName = "channel_"..tostring(ChannelWindow.currentSelection)
	ChatJoinChannel(ButtonGetText(windowName))
	DestroyWindow("ChannelWindow")
end

function ChannelWindow.Leave_OnLButtonUp()
	ChatLeaveChannel()
	DestroyWindow("ChannelWindow")
end

function ChannelWindow.Create_OnLButtonUp()
	CreateWindow("CreateChannelWindow", true)
end

function ChannelWindow.CreateCancel_OnLButtonUp()
	DestroyWindow("CreateChannelWindow")
end

function ChannelWindow.CreateChannel()
	local textEntry = TextEditBoxGetText("CreateChannelWindowTextEntry")
	ChatCreateChannel(textEntry)
	
	DestroyWindow("CreateChannelWindow")
	DestroyWindow("ChannelWindow")
end