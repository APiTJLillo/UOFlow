----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

PartyInviteWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

PartyInviteWindow.TID = {
	Title = 1115370,
	Accept = 1115371,
	Decline = 1115372,
	Dialog = 1115373,
	DoNotShow = 1115374
}

PartyInviteWindow.checkboxFlag = false

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function PartyInviteWindow.Initialize()
	Interface.DestroyWindowOnClose["PartyInviteWindow"] = true
	
	WindowUtils.SetWindowTitle("PartyInviteWindow", GetStringFromTid(PartyInviteWindow.TID.Title))
	ButtonSetText( "PartyInviteWindowAcceptButton", GetStringFromTid(PartyInviteWindow.TID.Accept) )
	ButtonSetText( "PartyInviteWindowDeclineButton", GetStringFromTid(PartyInviteWindow.TID.Decline) )
	
	LabelSetText("PartyInviteWindowDescriptionLabel", WindowData.PartyInviteName..GetStringFromTid(PartyInviteWindow.TID.Dialog))
	
	LabelSetText( "PartyInviteWindowShowOptionLabel", GetStringFromTid(PartyInviteWindow.TID.DoNotShow) )
	ButtonSetPressedFlag( "PartyInviteWindowShowOptionButton", false )
	
	WindowRegisterEventHandler( "PartyInviteWindow", SystemData.Events.CLOSE_PARTY_INVITE, "PartyInviteWindow.CloseWindow" )
end

function PartyInviteWindow.Shutdown()
	if (IsPartyRequestPending()) then
		DeclinePartyInvite()
	end
	
	local pressedFlag = ButtonGetPressedFlag("PartyInviteWindowShowOptionButton")
	if (pressedFlag) then
		SystemData.Settings.Interface.partyInvitePopUp = false
		SettingsWindow.UpdateSettings()
		UserSettingsChanged()
	end
end

function PartyInviteWindow.CloseWindow()
	DestroyWindow("PartyInviteWindow")
end

function PartyInviteWindow.Accept_OnLButtonUp()
	AcceptPartyInvite()
	DestroyWindow("PartyInviteWindow")
end

function PartyInviteWindow.Decline_OnLButtonUp()
	DeclinePartyInvite()
	DestroyWindow("PartyInviteWindow")
end

function PartyInviteWindow.Check_OnLButtonUp()
	PartyInviteWindow.checkboxFlag = not PartyInviteWindow.checkboxFlag
	ButtonSetPressedFlag("PartyInviteWindowShowOptionButton", PartyInviteWindow.checkboxFlag)
end