----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

StartMenu = {}
StartMenu.StartData["StartMenuButton"] = {}
StartMenu.StartData["StartMenuButton"].ToolTipTid = 1049755 -- Main Menu
StartMenu.StartData["StartMenuButton"].ToggleWindow = "MainMenuWindow"
StartMenu.StartData["StartMenuButton"].KeyBinding = nil

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

----------------------------------------------------------------
-- CharacterWindow Functions
----------------------------------------------------------------
function StartMenu.GetData()
    windowName = SystemData.ActiveWindow.name
    return StartMenu.StartData[windowName]
end

-- OnInitialize Handler
function StartMenu.Initialize()		
	ButtonSetPressedFlag( SystemData.ActiveWindow.name, false)
end

-- OnShutdown Handler
function StartMenu.Shutdown()

end

function StartMenu.ToggleStartMenu()	
	data = StartMenu.GetData()
	
	-- Setting ToggleWindow to nil indicates that we have to use a custom handler
    if (data.ToggleWindow) then
    	ToggleWindowByName(data.ToggleWindow, SystemData.ActiveWindow.name, StartMenu.ToggleMenuButton)	
    	ButtonSetPressedFlag( SystemData.ActiveWindow.name, false)
    end
end

function StartMenu.OnMouseoverStartMenuBtn()
	data = StartMenu.GetData()
	local btnName = SystemData.ActiveWindow.name
	
	if data ~= nil then
		text = GetStringFromTid(data.ToolTipTid)
		Tooltips.CreateTextOnlyTooltip(btnName, text)
		Tooltips.Finalize()
		Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	else
		Debug.Print(L"Tooltip data was nil")
	end 
end