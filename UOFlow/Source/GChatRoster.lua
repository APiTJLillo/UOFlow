----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

GChatRoster = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

GChatRoster.RemoveGChatIndex = 0

GChatRoster.TID = {
	Title = 1158422,
	Add_Friend = 3006110,
	Add_Friend_Detail = 1158421,
	Status = 1153034,
}
GChatRoster.GC_SHOW_UNAVAILABLE = 0
GChatRoster.GC_SHOW_CHAT = 1

GChatRoster.Presence = {}
GChatRoster.Presence[1] = {tid = 1070798, id = GChatRoster.GC_SHOW_UNAVAILABLE}
GChatRoster.Presence[2] = {tid = 1063015, id = GChatRoster.GC_SHOW_CHAT}
GChatRoster.NUM_PRESENCE = 2

GChatRoster.DEFAULT_START_POSITION = {
x = 300,
y = 300,
}

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function GChatRoster.Initialize()
	Interface.DestroyWindowOnClose["GChatRoster"] = true
	
	WindowUtils.SetWindowTitle("GChatRoster", GetStringFromTid(GChatRoster.TID.Title))
		
    WindowRegisterEventHandler( "GChatRoster", SystemData.Events.GHAT_ROSTER_UPDATE,       "GChatRoster.OnGChatRosterUpdate") 
    WindowRegisterEventHandler( "GChatRoster", SystemData.Events.GHAT_MY_PRESENCE_UPDATE, "GChatRoster.OnGChatPresenceUpdate")
    WindowRegisterEventHandler( "GChatRoster", SystemData.Events.GHAT_PRESENCE_UPDATE,    "GChatRoster.UpdateFriendPresence")

	LabelSetText( "GChatRosterPresenceLabel", GetStringFromTid( GChatRoster.TID.Status ) )	
	for pres = 1, GChatRoster.NUM_PRESENCE do		
		local currentTID  = GChatRoster.Presence[pres].tid
		local text = GetStringFromTid(currentTID )		
		ComboBoxAddMenuItem( "GChatRosterPresenceCombo", L""..towstring(text) )
	end

	ButtonSetText( "GChatRosterAddFriendButton", GetStringFromTid(GChatRoster.TID.Add_Friend))
	GChatRoster.OnGChatRosterUpdate()
	GChatRoster.OnGChatPresenceUpdate()

	WindowUtils.RestoreWindowPosition("GChatRoster", false)
	if (Interface.GChatFirstPositioning or not WindowUtils.CanRestorePosition("GChatRoster")) and DoesWindowNameExist("GChatRoster") then		
		Interface.GChatFirstPositioning = nil
		local x, y;		
		x = GChatRoster.DEFAULT_START_POSITION.x
		y = GChatRoster.DEFAULT_START_POSITION.y		
		
		x = math.floor(x / InterfaceCore.scale + 0.5)
		y = math.floor(y / InterfaceCore.scale + 0.5)
		WindowClearAnchors("GChatRoster")
		WindowAddAnchor("GChatRoster", "topleft", "Root", "topleft", x, y)		
	end
end


function GChatRoster.Shutdown()	
	WindowUtils.SaveWindowPosition("GChatRoster")

	for i = 1, WindowData.GChatCount do		
		local currentFriend = "friend_"..tostring(i)
		if( DoesWindowNameExist(currentFriend) == true ) then
			
			DestroyWindow(currentFriend)
		end		
	end
end

function GChatRoster.OnGChatRosterUpdate()
    
	local previousFriend = nil
	local currentFriend = nil
	local texture = "UO_Core"	

	if(WindowData.RemoveGChatIndex > 0)then
		local windowToRemove = "friend_"..tostring(WindowData.GChatCount+1)		
		DestroyWindow(windowToRemove)
		WindowData.RemoveGChatIndex = 0
	end

	if(WindowData.GChatCount == 0)then
		currentFriend = "friend_"..tostring(1)		
		if( DoesWindowNameExist(currentFriend) == true ) then			
			DestroyWindow(currentFriend)
		end
	end

	local activeFriend = nil
	for i = 1, WindowData.GChatCount do		
		currentFriend = "friend_"..tostring(i)
		if( DoesWindowNameExist(currentFriend) == true ) then			
			DestroyWindow(currentFriend)
		end

		CreateWindowFromTemplate( currentFriend, "GChatRosterListItemTemplate", "GChatRosterContent" )
		
		WindowSetShowing(currentFriend, true)
		local currentFriendPresenceButton = currentFriend.."Presence"
		local currentFriendPresenceOfflineButton = currentFriendPresenceButton.."Offline"
		local currentFriendPresenceOnlineButton = currentFriendPresenceButton.."Online"
		local currentFriendNameButton = currentFriend.."Name"
		
		local friendPresence = WindowData.GChatPresenceList[i]
		local friendName = towstring(WindowData.GChatNameList[i])

		WindowSetId(currentFriendPresenceOfflineButton, i)
		WindowSetId(currentFriendPresenceOnlineButton, i)
		WindowSetId(currentFriendNameButton, i)
		WindowSetId(currentFriend.."Remove", i)
		ButtonSetText(currentFriendNameButton, friendName)
		ButtonSetPressedFlag(currentFriendNameButton, false)

		if(WindowData.GChatIndex == i)then		
			ButtonSetPressedFlag(currentFriendNameButton, true)
			activeFriend = currentFriend
		end
		
		if ( friendPresence == 1 ) then	
			WindowSetShowing(currentFriendPresenceOnlineButton, true);
			WindowSetShowing(currentFriendPresenceOfflineButton, false);
		else
			WindowSetShowing(currentFriendPresenceOnlineButton, false);
			WindowSetShowing(currentFriendPresenceOfflineButton, true);
		end
		
		if (previousFriend == nil) then
			WindowAddAnchor(currentFriend, "topleft", "GChatRosterContent", "topleft", 0, 0)			
		else
			WindowAddAnchor(currentFriend, "bottomleft", previousFriend, "topleft", 0, 0)
		end
		previousFriend = currentFriend
	end
	
	ScrollWindowUpdateScrollRect("GChatRosterScrollWindow")


	if activeFriend ~= nil then
        WindowUtils.ScrollToElementInScrollWindow( activeFriend, "GChatRosterScrollWindow", "GChatRosterContent" )
    end
end

function GChatRoster.OnGChatPresenceUpdate()

    for pres = 1, GChatRoster.NUM_PRESENCE do
		if( WindowData.GChatMyPresence ==  GChatRoster.Presence[pres].id )then
			ComboBoxSetSelectedMenuItem( "GChatRosterPresenceCombo", pres )
		end
	end
end

function GChatRoster.RemoveTooltip()		
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(3006099))	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function GChatRoster.OnlineTooltip()		
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1079366))	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function GChatRoster.OfflineTooltip()		
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name, GetStringFromTid(1070798))	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function GChatRoster.SelectActiveFriend(override)	
	 local friendSelection = SystemData.ActiveWindow.name
	 if (override == nil or override ==0) then	
     	WindowData.GChatIndex = WindowGetId(friendSelection)
     end     

     for i = 1, WindowData.GChatCount do		
		local currentFriend = "friend_"..tostring(i)

		local currentFriendPresenceButton = currentFriend.."Presence"
		local currentFriendPresenceOfflineButton = currentFriendPresenceButton.."Offline"
		local currentFriendPresenceOnlineButton = currentFriendPresenceButton.."Online"
		local currentFriendNameButton = currentFriend.."Name"
		
		local friendPresence = WindowData.GChatPresenceList[i]
		local friendName = towstring(WindowData.GChatNameList[i])		
		ButtonSetPressedFlag(currentFriendNameButton, false)
		if(WindowData.GChatIndex == i)then		
			ButtonSetPressedFlag(currentFriendNameButton, true)
		end		
	end
		
	if(override == nil or override ==0)then
		ChatWindow.firstGChatSelect = false
		ChatWindow.OnGChatRosterUpdate()  
		ChatWindow.SwitchToGChatSelectedChannel()
	elseif(ChatWindow.firstGChatSelect)then
    	WindowData.GChatIndex = WindowData.GChatIndex + 1    
	end
	
end


function GChatRoster.UpdateFriendPresence()	
	 local friendSelection = SystemData.ActiveWindow.name     
     
     for i = 1, WindowData.GChatCount do		
		local currentFriend = "friend_"..tostring(i)		
		local currentFriendPresenceButton = currentFriend.."Presence"
		local currentFriendPresenceOfflineButton = currentFriendPresenceButton.."Offline"
		local currentFriendPresenceOnlineButton = currentFriendPresenceButton.."Online"		

		local friendPresence = WindowData.GChatPresenceList[i]			
		if ( friendPresence == 1 ) then	
			WindowSetShowing(currentFriendPresenceOnlineButton, true);
			WindowSetShowing(currentFriendPresenceOfflineButton, false);
		else
			WindowSetShowing(currentFriendPresenceOnlineButton, false);
			WindowSetShowing(currentFriendPresenceOfflineButton, true);
		end
	end
	
end


function GChatRoster.RemoveFriend()	
	if(WindowData.GChatMyPresence == GChatRoster.GC_SHOW_CHAT)then
		local friendSelection = SystemData.ActiveWindow.name
	    WindowData.RemoveGChatIndex = WindowGetId(friendSelection)	
		BroadcastEvent( SystemData.Events.REMOVE_GLOBAL_CHAT_FRIEND )
	end
end


function GChatRoster.OnAddFriend()
	if(WindowData.GChatMyPresence == GChatRoster.GC_SHOW_CHAT)then
		BroadcastEvent( SystemData.Events.ADD_GLOBAL_CHAT_FRIEND)				
	end
end

function GChatRoster.OnPresenceChange()

	local presIndex = ComboBoxGetSelectedMenuItem( "GChatRosterPresenceCombo" )
	WindowData.GChatMyPresence = GChatRoster.Presence[presIndex].id
	BroadcastEvent( SystemData.Events.TOGGLE_GLOBAL_CHAT_PRESENCE )
end