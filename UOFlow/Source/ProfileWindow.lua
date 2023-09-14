----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ProfileWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

ProfileWindow.WindowName = "ProfileWindow"
ProfileWindow.ProfileLoaded = false
ProfileWindow.ProfileId = 0

ProfileWindow.delta = 0
ProfileWindow.Retries = 0

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function ProfileWindow.Initialize()
	WindowSetDimensions(ProfileWindow.WindowName, 400,500)
	WindowSetDimensions(ProfileWindow.WindowName .. "Top", 433,43)
	WindowSetDimensions(ProfileWindow.WindowName .. "Bottom", 433,18)
	WindowSetShowing(ProfileWindow.WindowName, false)
	WindowUtils.RestoreWindowPosition(ProfileWindow.WindowName)
	ProfileWindow.ProfileLoaded = false
	ProfileWindow.ProfileId = 0

	TextEditBoxSetFont(ProfileWindow.WindowName.."ProfileEditScrollWChildText",  "font_verdana")
	LabelSetFont(ProfileWindow.WindowName.."ProfileViewScrollChildText",  "UO_DefaultText_15pt", 15)
	ProfileWindow.UpdateProfile()
end

function ProfileWindow.Shutdown()
	local playerId = WindowData.PlayerStatus.PlayerId
	if (ProfileWindow.ProfileId == playerId) then
		local infoText = TextEditBoxGetText(ProfileWindow.WindowName.."ProfileEditScrollWChildText")		
		UpdateCharProfile(ProfileWindow.ProfileId,infoText)				
	end
    WindowUtils.SaveWindowPosition(ProfileWindow.WindowName)
    SnapUtils.SnappableWindows["ProfileWindow"] = nil
end

function ProfileWindow.TextChange()
	local x,y = WindowGetDimensions(ProfileWindow.WindowName.."ProfileEditScrollWChildText")
	y = y + 100
	WindowSetDimensions(ProfileWindow.WindowName.."ProfileEditScrollWChild", x, y)	
	ScrollWindowUpdateScrollRect( ProfileWindow.WindowName.."ProfileEditScrollW" )
end

function ProfileWindow.Close()	
	local playerId = WindowData.PlayerStatus.PlayerId	
	if (ProfileWindow.ProfileId == playerId) then
		local infoText = TextEditBoxGetText(ProfileWindow.WindowName.."ProfileEditScrollWChildText")		
		UpdateCharProfile(ProfileWindow.ProfileId,infoText)				
	end
	TextEditBoxSetText(ProfileWindow.WindowName.."ProfileEditScrollWChildText",L"")
	LabelSetText(ProfileWindow.WindowName.."ProfileViewScrollChildText",L"")
	WindowUtils.SaveWindowPosition(ProfileWindow.WindowName)
	local windowName = "PaperdollWindow"..ProfileWindow.ProfileId
	
	WindowSetShowing("ProfileWindow", false)
	ProfileWindow.ProfileLoaded = false
	ProfileWindow.ProfileId = 0
end

function ProfileWindow.UpdateProfile()		
	BroadcastEvent(SystemData.Events.REQUEST_OPEN_CHAR_PROFILE)	
end