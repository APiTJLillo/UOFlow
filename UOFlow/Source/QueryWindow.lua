----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

QueryWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

QueryWindow.lastWindowAnchor = ""
QueryWindow.xDimensions = 0
QueryWindow.yDimensions = 0

QueryWindow.TID = {
	Title = 1112448,
	Header = 1113964,
	Okay = 3000093,
	LegacyMacroImporter = 1112449,
	YesPlease = 1113951,
	NoThanks = 1113952,
	QueryLegacySettings = 1113960,
	UseEnhancedSettings = 1113961,
	UseLegacySettings = 1113962,
	DoNotChangeSettings = 1113963
}

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function QueryWindow.Initialize()
	WindowRegisterEventHandler( "Root", SystemData.Events.UPDATE_QUERY_WINDOW, "QueryWindow.CheckQueries" )
	
	QueryWindow.CheckQueries()
end

function QueryWindow.CheckQueries()
	if( DoesWindowExist("MainQueryWindow") ) then
		DestroyWindow("MainQueryWindow")
	end
	
	QueryWindow.CheckQueriedLegacySettings()
	QueryWindow.CheckScannedLegacyMacros()
end

function QueryWindow.CreateQueryWindow()
	CreateWindowFromTemplate( "MainQueryWindow", "QueryWindowTemplate", "Root" )
	Interface.DestroyWindowOnClose["MainQueryWindow"] = true
	
	QueryWindow.lastWindowAnchor = "MainQueryWindowText"
	
	WindowUtils.SetWindowTitle("MainQueryWindow", GetStringFromTid(QueryWindow.TID.Title))
	LabelSetText( "MainQueryWindowText", GetStringFromTid(QueryWindow.TID.Header) )
	ButtonSetText( "MainQueryWindowOkayButton", GetStringFromTid(QueryWindow.TID.Okay) )
	
	QueryWindow.xDimensions = 620
	QueryWindow.yDimensions = 118
	
	WindowSetDimensions("MainQueryWindow", QueryWindow.xDimensions, QueryWindow.yDimensions)
end

function QueryWindow.CheckScannedLegacyMacros()
	if( SystemData.Settings.Interface.scannedLegacyMacros == false and MacroSystemDoLegacyMacrosExist() == true ) then
		if( not DoesWindowExist("MainQueryWindow") ) then
			QueryWindow.CreateQueryWindow()
		end
		
		CreateWindowFromTemplate( "ScannedLegacyMacrosWindow", "QueryWindowTwoSelectionTemplate", "MainQueryWindow" )
		
		WindowClearAnchors("ScannedLegacyMacrosWindow")
		WindowAddAnchor("ScannedLegacyMacrosWindow", "bottomleft", QueryWindow.lastWindowAnchor, "topleft", 0, 0)
		QueryWindow.lastWindowAnchor = "ScannedLegacyMacrosWindow"
		
		LabelSetText( "ScannedLegacyMacrosWindowText", GetStringFromTid(QueryWindow.TID.LegacyMacroImporter) )
		LabelSetText( "ScannedLegacyMacrosWindowButtonOneLabel", GetStringFromTid(QueryWindow.TID.YesPlease) )
		LabelSetText( "ScannedLegacyMacrosWindowButtonTwoLabel", GetStringFromTid(QueryWindow.TID.NoThanks) )
		
		ButtonSetStayDownFlag("ScannedLegacyMacrosWindowButtonOneButton", true)
		ButtonSetStayDownFlag("ScannedLegacyMacrosWindowButtonTwoButton", true)
		
		ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonOneButton", true )
		ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonTwoButton", false )
		
		WindowRegisterCoreEventHandler("ScannedLegacyMacrosWindowButtonOneButton", "OnLButtonUp", "QueryWindow.ScannedLegacyMacros_OptionOne_OnLButtonUp")
		WindowRegisterCoreEventHandler("ScannedLegacyMacrosWindowButtonTwoButton", "OnLButtonUp", "QueryWindow.ScannedLegacyMacros_OptionTwo_OnLButtonUp")
		
		local x, y = _WindowGetDimensions("ScannedLegacyMacrosWindowText")
		WindowSetDimensions("ScannedLegacyMacrosWindow", x, y+81)
		
		QueryWindow.yDimensions = QueryWindow.yDimensions + y + 81
		WindowSetDimensions("MainQueryWindow", QueryWindow.xDimensions, QueryWindow.yDimensions)
		
		SystemData.Settings.Interface.scannedLegacyMacrosSelection = 1
	end
end

function QueryWindow.CheckQueriedLegacySettings()
	if( SystemData.Settings.Interface.queriedLegacySettings == false ) then
		if( not DoesWindowExist("MainQueryWindow") ) then
			QueryWindow.CreateQueryWindow()
		end
		
		CreateWindowFromTemplate( "QueriedLegacySettingsWindow", "QueryWindowThreeSelectionTemplate", "MainQueryWindow" )
	
		WindowClearAnchors("QueriedLegacySettingsWindow")
		WindowAddAnchor("QueriedLegacySettingsWindow", "bottomleft", QueryWindow.lastWindowAnchor, "topleft", 0, 0)
		QueryWindow.lastWindowAnchor = "QueriedLegacySettingsWindow"
		
		LabelSetText( "QueriedLegacySettingsWindowText", GetStringFromTid(QueryWindow.TID.QueryLegacySettings) )
		LabelSetText( "QueriedLegacySettingsWindowButtonOneLabel", GetStringFromTid(QueryWindow.TID.UseEnhancedSettings) )
		LabelSetText( "QueriedLegacySettingsWindowButtonTwoLabel", GetStringFromTid(QueryWindow.TID.UseLegacySettings) )
		LabelSetText( "QueriedLegacySettingsWindowButtonThreeLabel", GetStringFromTid(QueryWindow.TID.DoNotChangeSettings) )
		
		ButtonSetStayDownFlag("QueriedLegacySettingsWindowButtonOneButton", true)
		ButtonSetStayDownFlag("QueriedLegacySettingsWindowButtonTwoButton", true)
		ButtonSetStayDownFlag("QueriedLegacySettingsWindowButtonThreeButton", true)
		
		ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonOneButton", true )
		ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonTwoButton", false )
		ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonThreeButton", false )
		
		WindowRegisterCoreEventHandler("QueriedLegacySettingsWindowButtonOneButton", "OnLButtonUp", "QueryWindow.QueriedLegacySettings_OptionOne_OnLButtonUp")
		WindowRegisterCoreEventHandler("QueriedLegacySettingsWindowButtonTwoButton", "OnLButtonUp", "QueryWindow.QueriedLegacySettings_OptionTwo_OnLButtonUp")
		WindowRegisterCoreEventHandler("QueriedLegacySettingsWindowButtonThreeButton", "OnLButtonUp", "QueryWindow.QueriedLegacySettings_OptionThree_OnLButtonUp")
		
		local x, y = _WindowGetDimensions("QueriedLegacySettingsWindowText")
		WindowSetDimensions("QueriedLegacySettingsWindow", x, y+108)
		
		QueryWindow.yDimensions = QueryWindow.yDimensions + y + 108
		WindowSetDimensions("MainQueryWindow", QueryWindow.xDimensions, QueryWindow.yDimensions)
		
		SystemData.Settings.Interface.queriedLegacySettingsSelection = 1
	end
end

function QueryWindow.ScannedLegacyMacros_OptionOne_OnLButtonUp()
	ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonOneButton", true )
	ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonTwoButton", false )
	
	SystemData.Settings.Interface.scannedLegacyMacrosSelection = 1
end

function QueryWindow.ScannedLegacyMacros_OptionTwo_OnLButtonUp()
	ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonOneButton", false )
	ButtonSetPressedFlag( "ScannedLegacyMacrosWindowButtonTwoButton", true )
	
	SystemData.Settings.Interface.scannedLegacyMacrosSelection = 2
end

function QueryWindow.QueriedLegacySettings_OptionOne_OnLButtonUp()
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonOneButton", true )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonTwoButton", false )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonThreeButton", false )
	
	SystemData.Settings.Interface.queriedLegacySettingsSelection = 1
end

function QueryWindow.QueriedLegacySettings_OptionTwo_OnLButtonUp()
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonOneButton", false )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonTwoButton", true )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonThreeButton", false )
	
	SystemData.Settings.Interface.queriedLegacySettingsSelection = 2
end

function QueryWindow.QueriedLegacySettings_OptionThree_OnLButtonUp()
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonOneButton", false )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonTwoButton", false )
	ButtonSetPressedFlag( "QueriedLegacySettingsWindowButtonThreeButton", true )
	
	SystemData.Settings.Interface.queriedLegacySettingsSelection = 3
end

function QueryWindow.Okay_OnLButtonUp()
	BroadcastEvent(SystemData.Events.QUERY_WINDOW_PROCESS_SELECTIONS)

	DestroyWindow("MainQueryWindow")
end