----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

TipoftheDayWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

TipoftheDayWindow.tipIndex = 0
TipoftheDayWindow.saveOnClose = false

TipoftheDayWindow.TID = { TipoftheDay = 1094689, DoNotShow = 1094690, Next = 1043353, Close = 1052061 }

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function TipoftheDayWindow.Initialize()
	Interface.DestroyWindowOnClose["TipoftheDayWindow"] = true
		
	-- BT TODO: REPLACE TEXT WITH TID
	-- Set window text
	WindowUtils.SetWindowTitle("TipoftheDayWindow", GetStringFromTid(TipoftheDayWindow.TID.TipoftheDay) )
	
	LabelSetText( "TipoftheDayWindowShowOptionLabel", GetStringFromTid(TipoftheDayWindow.TID.DoNotShow) )
	
	ButtonSetText("TipoftheDayWindowNext", GetStringFromTid(TipoftheDayWindow.TID.Next) )
	ButtonSetText("TipoftheDayWindowClose", GetStringFromTid(TipoftheDayWindow.TID.Close) )
	
	ButtonSetPressedFlag( "TipoftheDayWindowShowOptionButton", not SystemData.Settings.Interface.showTipoftheDay )

	-- Load up the Tip of the Day data
	UOBuildTableFromCSV("Data/GameData/tipoftheday.csv", "TipoftheDayCSV")

	-- Select and display a tip	
	TipoftheDayWindow.GetRandomTip()
	WindowUtils.RestoreWindowPosition("TipoftheDayWindow")
end

function TipoftheDayWindow.Shutdown()
	SettingsWindow.UpdateSettings()
	-- push the new values to c++
	UserSettingsChanged()
	
	UOUnloadCSVTable("TipoftheDayCSV")
	WindowUtils.SaveWindowPosition("TipoftheDayWindow")
end

function TipoftheDayWindow.GetRandomTip()
	TipoftheDayWindow.tipIndex = GetRandomNumber( table.getn( WindowData.TipoftheDayCSV ) ) + 1
	LabelSetText( "TipoftheDayWindowText", GetStringFromTid( WindowData.TipoftheDayCSV[TipoftheDayWindow.tipIndex].TipTID ) )
end

function TipoftheDayWindow.ButtonUpNext()
	TipoftheDayWindow.tipIndex = TipoftheDayWindow.tipIndex + 1
	
	if( TipoftheDayWindow.tipIndex > table.getn( WindowData.TipoftheDayCSV ) ) then
		TipoftheDayWindow.tipIndex = 1
	end
	
	LabelSetText( "TipoftheDayWindowText", GetStringFromTid( WindowData.TipoftheDayCSV[TipoftheDayWindow.tipIndex].TipTID ) )
end

function TipoftheDayWindow.ButtonUpClose()
	DestroyWindow("TipoftheDayWindow")
end

function TipoftheDayWindow.ButtonUpShowOption()
	SystemData.Settings.Interface.showTipoftheDay = not SystemData.Settings.Interface.showTipoftheDay
	ButtonSetPressedFlag( "TipoftheDayWindowShowOptionButton", not SystemData.Settings.Interface.showTipoftheDay )
	
	TipoftheDayWindow.saveOnClose = true
end