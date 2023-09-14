----------------------------------------------------------------
-- Local Functions (placed here to avoid dependency issues)
----------------------------------------------------------------

----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

EA_Window_ContextMenu = {}
EA_Window_ContextMenu.activeWindow = nil
--[[EA_Window_ContextMenu.numMenuItems = 0
EA_Window_ContextMenu.numActiveMenuItems = 0
EA_Window_ContextMenu.anchorWindow = "EA_Window_ContextMenu"
EA_Window_ContextMenu.functionTable = {}
EA_Window_ContextMenu.greatestWidth = 0--]]
EA_Window_ContextMenu.contextMenus = {}
EA_Window_ContextMenu.numContextMenus = 0
EA_Window_ContextMenu.CONTEXT_MENU_1 = 1
EA_Window_ContextMenu.CONTEXT_MENU_2 = 2
EA_Window_ContextMenu.CONTEXT_MENU_3 = 3
EA_Window_ContextMenu.MIN_WIDTH = 245

EA_Window_ContextMenu.MINIMUM_X_OFFSET = 10
----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

local function CreateContextMenu( windowName )
    if( not DoesWindowExist( windowName ) )
    then
        CreateWindowFromTemplate( windowName, "EA_Window_ContextMenu", "Root" )
    end
    
    EA_Window_ContextMenu.numContextMenus = EA_Window_ContextMenu.numContextMenus + 1
    WindowSetId( windowName, EA_Window_ContextMenu.numContextMenus )
    EA_Window_ContextMenu.contextMenus[ EA_Window_ContextMenu.numContextMenus ] =
    {
        numMenuItems = 0,
        numActiveMenuItems = 0,
        name = windowName,
        anchorWindow = name,
        functionTable = {},
        greatestWidth = 0,
        numUserDefinedMenuItems = 0,
        userDefinedMenuItems = {},
    }
    WindowSetShowing( windowName, false )
end

----------------------------------------------------------------
-- Context Menu Functions
----------------------------------------------------------------

-- OnInitialize Handler
function EA_Window_ContextMenu.Initialize()
    EA_Window_ContextMenu.numContextMenus = 0
    
    -- Create three context menus
    for index=1, 3
    do
        CreateContextMenu( "EA_Window_ContextMenu"..(EA_Window_ContextMenu.numContextMenus + 1) )
    end
    
    --Register events to close the window
    WindowRegisterEventHandler( "EA_Window_ContextMenu1", SystemData.Events.L_BUTTON_DOWN_PROCESSED, "EA_Window_ContextMenu.OnLButtonProcessed")
    WindowRegisterEventHandler( "EA_Window_ContextMenu1", SystemData.Events.R_BUTTON_DOWN_PROCESSED, "EA_Window_ContextMenu.OnRButtonProcessed")
    
    if( not DoesWindowExist( "EA_Window_SetOpacity") )
    then
        CreateWindow( "EA_Window_SetOpacity", false )
    end
    
    -- DAB TODO: Localize
    WindowUtils.SetWindowTitle("EA_Window_SetOpacity", L"Opacity" )
end

-- OnShutdown Handler
function EA_Window_ContextMenu.Shutdown()
end

function EA_Window_ContextMenu.Show( contextMenuNumber )
    local windowName = "EA_Window_ContextMenu1"
    if( contextMenuNumber )
    then
        windowName = "EA_Window_ContextMenu"..contextMenuNumber
    end
    WindowSetShowing( windowName, true )
end

function EA_Window_ContextMenu.Hide( contextMenuNumber )
    local windowName = "EA_Window_ContextMenu1"
    if( contextMenuNumber )
    then
        windowName = "EA_Window_ContextMenu"..contextMenuNumber
    end
    WindowSetShowing( windowName, false )
end

function EA_Window_ContextMenu.HideAll()
    for index = 1, EA_Window_ContextMenu.numContextMenus
    do
        if( EA_Window_ContextMenu.contextMenus[index] )
        then
            WindowSetShowing( EA_Window_ContextMenu.contextMenus[index].name, false )
        end
    end
end

-- Call this first before adding any menu items... if just using the default context menu
-- this will be called for you in the function CreateDefaultContextMenu
-- If windowNameToActUpon is empty string  (""), then it uses the last known activeWindow
function EA_Window_ContextMenu.CreateContextMenu( windowNameToActUpon, contextMenuNumber )
    if( not contextMenuNumber )
    then
        contextMenuNumber = EA_Window_ContextMenu.CONTEXT_MENU_1
    end
    
    if ( windowNameToActUpon == "" ) 
    then
        windowNameToActUpon = EA_Window_ContextMenu.activeWindow
    end
    --Set up the ContextMenu for a new menu
    local contextMenu = EA_Window_ContextMenu.contextMenus[ contextMenuNumber ]
    if( contextMenu )
    then
        EA_Window_ContextMenu.activeWindow = windowNameToActUpon
        contextMenu.numActiveMenuItems = 0
        contextMenu.anchorWindow = contextMenu.name
        contextMenu.functionTable = {}
        contextMenu.greatestWidth = 0
        contextMenu.numUserDefinedMenuItems = 0
        
        for index, menuItemName in ipairs( contextMenu.userDefinedMenuItems )
        do
            WindowSetParent( menuItemName, "Root" )
            WindowSetShowing( menuItemName, false )
        end
        
        contextMenu.userDefinedMenuItems = {}
    end
end

-- Add a single menu item button to the context menu... bCloseAfterClick is whether you wish the context menu to
-- close after you have clicked on one of the buttons in it. This is useful if you were to spawn a sub menu off of
-- one of the buttons. You must specify which context menu you wish to add the menu item to.
-- If none is specified it will default to the first one.
function EA_Window_ContextMenu.AddMenuItem( buttonText, callbackFunction, bDisabled, bCloseAfterClick, contextMenuNumber, param )
    if( buttonText == nil       or
        buttonText == L""       or
        callbackFunction == nil ) then
        return
    end
    
    if( not contextMenuNumber )
    then
        contextMenuNumber = EA_Window_ContextMenu.CONTEXT_MENU_1
    end
    
    local contextMenu = EA_Window_ContextMenu.contextMenus[ contextMenuNumber ]
    
    if( not contextMenu )
    then
        return
    end
    
    contextMenu.numActiveMenuItems = contextMenu.numActiveMenuItems + 1
    local buttonWindowName = contextMenu.name.."Item"..contextMenu.numActiveMenuItems
    
    -- Create the window only if needed
    if( contextMenu.numMenuItems < contextMenu.numActiveMenuItems ) then
        contextMenu.numMenuItems = contextMenu.numMenuItems + 1
        CreateWindowFromTemplate( buttonWindowName, "EA_Button_ContextMenuItem", contextMenu.name )
    end
    
    -- Set up the function table
    contextMenu.functionTable[ contextMenu.numActiveMenuItems ] = {}
    contextMenu.functionTable[ contextMenu.numActiveMenuItems ].callbackFunction = callbackFunction
    contextMenu.functionTable[ contextMenu.numActiveMenuItems ].closeAfterClick = bCloseAfterClick
    contextMenu.functionTable[ contextMenu.numActiveMenuItems ].param = param
    
    -- Set up the button
    WindowSetDimensions( buttonWindowName, 1000, 28 )
    WindowSetId( buttonWindowName, contextMenu.numActiveMenuItems )
    ButtonSetText( buttonWindowName, buttonText )
    ButtonSetDisabledFlag( buttonWindowName, bDisabled )
    
    -- Record the width of the largest button for determining the width of the overall window
    local x, y = WindowGetDimensions( buttonWindowName )
    if( x > contextMenu.greatestWidth )
    then
        contextMenu.greatestWidth = x
    end
    
    -- Anchor the window to the menu
    WindowClearAnchors( buttonWindowName )
    if( contextMenu.numActiveMenuItems == 1 and contextMenu.numUserDefinedMenuItems < 1 )
    then
        WindowAddAnchor( buttonWindowName, "topleft", contextMenu.anchorWindow, "topleft", 5, 5 )
    else
        WindowAddAnchor( buttonWindowName, "bottomleft", contextMenu.anchorWindow, "topleft", 0, 0 )
    end
    
    contextMenu.anchorWindow = buttonWindowName 
end

-- Add a single user defined window to the context menu.
-- The window must already exist and have its own callbacks and event handlers specified.
-- The context menu will take care of hiding and showing the menu item as well as anchoring it.
-- You must specify which context menu you wish to add the menu item to.
-- If none is specified it will default to the first one.
function EA_Window_ContextMenu.AddUserDefinedMenuItem( windowName, contextMenuNumber )
    if( windowName == nil or windowName == "" ) then
        return
    end
    
    if( not contextMenuNumber )
    then
        contextMenuNumber = EA_Window_ContextMenu.CONTEXT_MENU_1
    end
    
    local contextMenu = EA_Window_ContextMenu.contextMenus[ contextMenuNumber ]
    
    if( not contextMenu )
    then
        return
    end
    
    contextMenu.numUserDefinedMenuItems = contextMenu.numUserDefinedMenuItems + 1
    contextMenu.userDefinedMenuItems[ contextMenu.numUserDefinedMenuItems ] = windowName
    
    -- Set up the button
    WindowSetId( windowName, contextMenu.numUserDefinedMenuItems )
    WindowSetParent( windowName, contextMenu.name )
    
    -- Record the width of the largest button for determining the width of the overall window
    local x, y = WindowGetDimensions( windowName )
    if( x > contextMenu.greatestWidth )
    then
        contextMenu.greatestWidth = x
    end
    
    -- Anchor the window to the menu
    WindowClearAnchors( windowName )
    if( contextMenu.numUserDefinedMenuItems == 1 and contextMenu.numActiveMenuItems < 1 )
    then
        WindowAddAnchor( windowName, "topleft", contextMenu.anchorWindow, "topleft", 5, 5 )
    else
        WindowAddAnchor( windowName, "bottomleft", contextMenu.anchorWindow, "topleft", 0, 0 )
    end
    contextMenu.anchorWindow = windowName 
end

-- Completes the menu and calls Show( contextMenuNumber ). You need to call this after adding all your menu items to a Context Menu.
-- anchor is a Table with all information of where the Context Menu should be anchored. 
-- It contains {Point, RelativePoint, RelativeTo, XOffset, YOffset} values.
function EA_Window_ContextMenu.Finalize( contextMenuNumber, anchor )
    if( not contextMenuNumber )
    then
        contextMenuNumber = EA_Window_ContextMenu.CONTEXT_MENU_1
    end
    
    local contextMenu = EA_Window_ContextMenu.contextMenus[ contextMenuNumber ]
    
    if( not contextMenu or contextMenu.numActiveMenuItems < 1 and contextMenu.numUserDefinedMenuItems < 1 )
    then
        return
    end
    
    -- set the new dimensions of the window
    -- according to how many active buttons ther are
    local x = 0
    local y = 0
    local numItemsInContextMenu = contextMenu.numActiveMenuItems + contextMenu.numUserDefinedMenuItems

    -- Show/Hide the appropriate number of menu items windows.
    for index = 1, contextMenu.numMenuItems
    do
        local show = index <= contextMenu.numActiveMenuItems
        local windowName = contextMenu.name.."Item"..index
        if( WindowGetShowing( windowName ) ~= show )
        then
            WindowSetShowing( windowName, show ) 
        end
        
        if( show )
        then
            local tempX = ButtonGetTextDimensions( windowName )
            local _, tempY = WindowGetDimensions( windowName )
            -- Text dimensions doesn't take in to account text offset, so add the margins in
            x = math.max( tempX + 15, x )
            y = y + tempY
        end
    end
    
    for index, windowName in ipairs( contextMenu.userDefinedMenuItems )
    do
        local tempX, tempY = WindowGetDimensions( windowName )
        x = math.max( tempX, x )
        y = y + tempY
        WindowSetShowing( windowName, true )
    end
    
    x = math.max( EA_Window_ContextMenu.MIN_WIDTH, x )
    
    for index = 1, contextMenu.numActiveMenuItems
    do
        local windowName = contextMenu.name.."Item"..index
        local _, tempY = WindowGetDimensions( windowName )
        WindowSetDimensions( windowName, x, tempY )
    end
    
    WindowSetDimensions( contextMenu.name, x + 8, y + 8 )
    
    local relativeWindow = "Root"
    local point, relativePoint
    if( contextMenuNumber == EA_Window_ContextMenu.CONTEXT_MENU_1 )
    then
        if (not anchor)
        then
            x = SystemData.MousePosition.x / InterfaceCore.scale
            y = SystemData.MousePosition.y / InterfaceCore.scale
            x = x + EA_Window_ContextMenu.MINIMUM_X_OFFSET
            point = "topleft"
            relativePoint = "topleft"
        else
            -- anchor was specified, use this information.
            x = anchor.XOffset
            y = anchor.YOffset
            point = anchor.Point
            relativePoint = anchor.RelativePoint
            relativeWindow = anchor.RelativeTo
        end
    else
        if (not anchor)
        then
            x = 2
            y = -4
            point = "topright"
            relativePoint = "topleft"
            relativeWindow = SystemData.MouseOverWindow.name
        else
            -- anchor was specified, use this information.
            x = anchor.XOffset
            y = anchor.YOffset
            point = anchor.Point
            relativePoint = anchor.RelativePoint
            if (anchor.RelativeTo == "")
            then
                relativeWindow = SystemData.MouseOverWindow.name
            else
                relativeWindow = anchor.RelativeTo
            end
        end
    end
    
    WindowClearAnchors( contextMenu.name )
    WindowAddAnchor( contextMenu.name, point, relativeWindow, relativePoint, x, y )
    EA_Window_ContextMenu.Show( contextMenuNumber )
end

-- For default context menus just use this function in your OnRButtonUp
-- Callback functions
function EA_Window_ContextMenu.CreateDefaultContextMenu( windowNameToActUpon )
    if( windowNameToActUpon == nil or windowNameToActUpon == "" )
    then
        return
    end
    
    EA_Window_ContextMenu.CreateContextMenu( windowNameToActUpon, EA_Window_ContextMenu.CONTEXT_MENU_1 ) 
    local movable = WindowGetMovable( EA_Window_ContextMenu.activeWindow )

    -- DAB TODO: Localize
    EA_Window_ContextMenu.AddMenuItem( L"Lock", EA_Window_ContextMenu.OnLock, not movable, true, EA_Window_ContextMenu.CONTEXT_MENU_1 )
    EA_Window_ContextMenu.AddMenuItem( L"Unlock", EA_Window_ContextMenu.OnUnlock, movable, true, EA_Window_ContextMenu.CONTEXT_MENU_1 )
    EA_Window_ContextMenu.AddMenuItem( L"Set Opacity", EA_Window_ContextMenu.OnWindowOptionsSetAlpha, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1 )
    EA_Window_ContextMenu.Finalize( EA_Window_ContextMenu.CONTEXT_MENU_1 )
end

-- For default context menus with only the opacity setting just use this function in your OnRButtonUp
-- Callback functions
function EA_Window_ContextMenu.CreateOpacityOnlyContextMenu( windowNameToActUpon )
    if( windowNameToActUpon == nil or windowNameToActUpon == "" )
    then
        return
    end
    
    EA_Window_ContextMenu.CreateContextMenu( windowNameToActUpon, EA_Window_ContextMenu.CONTEXT_MENU_1 ) 
    -- DAB TODO: Localize
    EA_Window_ContextMenu.AddMenuItem( L"Set Opacity", EA_Window_ContextMenu.OnWindowOptionsSetAlpha, false, true, EA_Window_ContextMenu.CONTEXT_MENU_1 )
    EA_Window_ContextMenu.Finalize( EA_Window_ContextMenu.CONTEXT_MENU_1 )
end

function EA_Window_ContextMenu.OnLButtonDownMenuItem()
    local clickedWindowName = SystemData.ActiveWindow.name
    if( ButtonGetDisabledFlag( clickedWindowName ) == true ) then
        return
    end
    
    local windowId = WindowGetId( clickedWindowName )
    local contextMenuId = WindowGetId( WindowGetParent( clickedWindowName ) )
    if ( windowId ~= nil and EA_Window_ContextMenu.contextMenus[contextMenuId].functionTable[windowId] ~= nil ) then
		local param = EA_Window_ContextMenu.contextMenus[contextMenuId].functionTable[windowId].param
        EA_Window_ContextMenu.contextMenus[contextMenuId].functionTable[windowId].callbackFunction(param)
        if( EA_Window_ContextMenu.contextMenus[contextMenuId].functionTable[windowId].closeAfterClick ) then
            EA_Window_ContextMenu.HideAll()
        end
    end
end

function EA_Window_ContextMenu.OnLButtonProcessed()
    local contextMenuName = "EA_Window_ContextMenu"
    local wndName = SystemData.MouseOverWindow.name 
    while wndName ~= nil
        and wndName ~= ""
        and wndName ~= "NONE"         
        and DoesWindowExist( wndName) do
        if (string.sub( wndName, 1, string.len(contextMenuName)) == contextMenuName)
        then
            return
        end
        wndName = WindowGetParent(wndName)
    end
    
    EA_Window_ContextMenu.HideAll()
end

function EA_Window_ContextMenu.OnRButtonProcessed()
    local contextMenuName = "EA_Window_ContextMenu"
    local wndName = SystemData.MouseOverWindow.name 
    while wndName ~= nil
        and wndName ~= ""
        and wndName ~= "NONE"         
        and DoesWindowExist( wndName) do
        if (string.sub( wndName, 1, string.len(contextMenuName)) == contextMenuName)
        then
            return
        end
        wndName = WindowGetParent(wndName)
    end
    EA_Window_ContextMenu.HideAll()
end


function EA_Window_ContextMenu.OnLock()
    WindowSetMovable( EA_Window_ContextMenu.activeWindow, false )   
end

function EA_Window_ContextMenu.OnUnlock()    
    WindowSetMovable( EA_Window_ContextMenu.activeWindow, true ) 
end

function EA_Window_ContextMenu.OnWindowOptionsSetAlpha()
    -- Open the Alpha Slider    
    local alpha = WindowGetAlpha( EA_Window_ContextMenu.activeWindow )    
    SliderBarSetCurrentPosition("EA_Window_SetOpacitySlider", alpha )    
    
    -- Anchor the OpacityWindow in the middle of the active window.
    WindowClearAnchors( "EA_Window_SetOpacity" )
    WindowAddAnchor( "EA_Window_SetOpacity", "center", EA_Window_ContextMenu.activeWindow, "center", 0 , 0 )

    WindowSetShowing( "EA_Window_SetOpacity", true )
end

function EA_Window_ContextMenu.OnSlideWindowOptionsAlpha( slidePos )
    local alpha = slidePos
    
    -- Requirements call for 10%-100% range, not 0% to 100%.
    if (alpha < 0.1) then
        alpha = 0.1
    end
    -- this if statement is a stop gap to prevent this call from happening with a bad window
    -- the bad call when using ctrl+alt+del should be tracked down
    if (EA_Window_ContextMenu.activeWindow ~= nil) then
        WindowSetAlpha( EA_Window_ContextMenu.activeWindow, alpha )
    end
end

function EA_Window_ContextMenu.CloseSetOpacityWindow()
    WindowSetShowing( "EA_Window_SetOpacity", false )
end

function EA_Window_ContextMenu.TrapClick()
end