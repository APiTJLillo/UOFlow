
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

Tooltips = {}


-- Pre-Defined Anchor Modes

Tooltips.ANCHOR_WINDOW_LEFT = 1
Tooltips.ANCHOR_WINDOW_RIGHT = 2
Tooltips.ANCHOR_WINDOW_TOP = 3
Tooltips.ANCHOR_WINDOW_BOTTOM = 4

Tooltips.ANCHOR_SCREEN_BOTTOM_RIGHT = 5


-- Window - Relative Anchor Positions
Tooltips.ANCHOR_WINDOW_LEFT 	= { Point = "topleft",		RelativeTo = "", RelativePoint = "topright",	XOffset = -4, YOffset = 0 }
Tooltips.ANCHOR_WINDOW_RIGHT 	= { Point = "topright",		RelativeTo = "", RelativePoint = "topleft", XOffset = 4, YOffset = 0 }
Tooltips.ANCHOR_WINDOW_TOP		= { Point = "topleft",		RelativeTo = "", RelativePoint = "bottomleft",	XOffset = 0, YOffset = -4 }
Tooltips.ANCHOR_WINDOW_BOTTOM	= { Point = "bottomleft",	RelativeTo = "", RelativePoint = "topleft",	XOffset = 0, YOffset = 4 }

-- Default tooltip table dimensions
Tooltips.NUM_ROWS = 5
Tooltips.NUM_COLUMNS = 2
Tooltips.ROW_SPACING = 5
Tooltips.BORDER_SIZE = 9
Tooltips.MAX_WIDTH = 375

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

local currentMouseOverWindow = ""
local currentStyle  = 0
local currentAnchor = Tooltips.ANCHOR_RIGHT
local currentTooltipWindow = ""
local visible = false
local currentUpdateCallback = nil



----------------------------------------------------------------
-- Tooltip Functions
----------------------------------------------------------------

function Tooltips.Initialize()

	-- Create the Tooltip Windows
	
	CreateWindow( "DefaultTooltip", false )
	
	currentTooltipWindow = "DefaultTooltip"
	Tooltips.ClearTooltip()
end

local lastMouseOverWindow
function Tooltips.Update( timePassed )

	-- Hide the tooltip if the current mouseover target does not match
	-- the current window.
	if( visible ) then
			
		if( currentMouseOverWindow ~= SystemData.MouseOverWindow.name ) then
	
			--Debug.PrintToChat( L"TooltipWindow  = "..StringToWString(currentMouseOverWindow)..L", CurrentMouseOverWindow = "..StringToWString(SystemData.MouseOverWindow.name) )
			Tooltips.ClearTooltip()
		elseif( currentUpdateCallback ~= nil ) then
		    
		    -- Update the tooltip if it has a callback
		    currentUpdateCallback( timePassed )
		
		end
	end
	
	if( lastMouseOverWindow ~= SystemData.MouseOverWindow.name ) then
	
		--Debug.PrintToChat( L"MouseOverWindow  = "..StringToWString(SystemData.MouseOverWindow.name) )
		lastMouseOverWindow = SystemData.MouseOverWindow.name
	end

end


function Tooltips.ClearTooltip()

	if( currentTooltipWindow ~= "" ) then
		WindowSetShowing( currentTooltipWindow, false )		
		Tooltips.SetTooltipAlpha( 1.0 )
		
		if( currentTooltipWindow == "DefaultTooltip" ) then
		    -- Clear all tooltip text
		    for rowNum = 1, Tooltips.NUM_ROWS do
			    for colNum = 1, Tooltips.NUM_COLUMNS do
				    colName = currentTooltipWindow.."Row"..rowNum.."Col"..colNum.."Text"
				    WindowSetDimensions( colName, Tooltips.MAX_WIDTH, 0 )
				    LabelSetText( colName, L"" )
				    LabelSetTextColor( colName, 255, 255, 255 )	
				    LabelSetFont( colName, "UO_DefaultText", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING )			
			    end
		    end
		end
		
		currentUpdateCallback = nil
	end	
	
	
	
	visible = false	
end

function Tooltips.AnchorTooltipManual( anchorPoint, anchorToWindow, anchorRelativePoint, anchorOffsetX, anchorOffsetY )
	
	WindowClearAnchors( currentTooltipWindow )
	WindowAddAnchor( currentTooltipWindow, anchorPoint, anchorToWindow, anchorRelativePoint, anchorOffsetX, anchorOffsetY )
	
end

function Tooltips.AnchorTooltip( anchor )

	local anchorToWindow = anchor.RelativeTo

	if( anchorToWindow == ""  ) then
		
		anchorToWindow = currentMouseOverWindow
	
	end	
	
	WindowClearAnchors( currentTooltipWindow )
	WindowAddAnchor( currentTooltipWindow, anchor.Point, anchorToWindow, anchor.RelativePoint, anchor.XOffset, anchor.YOffset )	

end

-- Set Data function for STYLE_TEXT_ONLY
function Tooltips.CreateTextOnlyTooltip( mouseOverWindow, text )
	currentMouseOverWindow = mouseOverWindow
	
	Tooltips.ClearTooltip()
	
	currentTooltipWindow = "DefaultTooltip"

	if( text ~= nil ) then
		Tooltips.SetTooltipText( 1, 1, text )
		Tooltips.Finalize()
	end
	
	WindowSetShowing( currentTooltipWindow, true )

	visible = true
end

function Tooltips.CreateCustomTooltip( mouseOverWindow, tooltipWindow )
	currentMouseOverWindow = mouseOverWindow
	
	Tooltips.ClearTooltip()
	
	currentTooltipWindow = tooltipWindow
	
	WindowSetShowing( currentTooltipWindow, true )

	visible = true
end

function Tooltips.SetUpdateCallback( callbackFunction )
    currentUpdateCallback = callbackFunction
end

function Tooltips.SetTooltipAlpha( alpha )
		
	WindowSetAlpha( currentTooltipWindow, alpha )
	WindowSetFontAlpha( currentTooltipWindow, alpha )

end

function Tooltips.SetTooltipText( row, column, text )

	if( row < 0 or row > Tooltips.NUM_ROWS or 
		column < 0 or column > Tooltips.NUM_COLUMNS ) then
		return
	end
	
	local currentTooltipWindow = "DefaultTooltip"
	local name = currentTooltipWindow.."Row"..row.."Col"..column.."Text"
	LabelSetText( name, text )
end

function Tooltips.SetTooltipFont( row, column, font, linespacing )

	if( row < 0 or row > Tooltips.NUM_ROWS or 
		column < 0 or column > Tooltips.NUM_COLUMNS ) then
		return
	end

	local currentTooltipWindow = "DefaultTooltip"
	LabelSetFont( currentTooltipWindow.."Row"..row.."Col"..column.."Text", font, linespacing )

end

function Tooltips.SetTooltipColor( row, column, red, green, blue )

	if( row < 0 or row > Tooltips.NUM_ROWS or 
		column < 0 or column > Tooltips.NUM_COLUMNS ) then
		return
	end

	local currentTooltipWindow = "DefaultTooltip"
	LabelSetTextColor( currentTooltipWindow.."Row"..row.."Col"..column.."Text", red, green, blue )

end

function Tooltips.Finalize()
	
	-- Calculate new tooltip dimensions
	local newWidth = 0
	local newHeight = 0
    local numRows = 0
	--TextLogAddEntry( "Chat", 100, L"Finializing tooltip" )
	
	for rowNum = 1, Tooltips.NUM_ROWS do
		local rowWidth = 0
		local rowHeight = 0
		local bothColumns = true
		rowName = currentTooltipWindow.."Row"..rowNum
		local rowX, rowY = WindowGetDimensions( rowName )

		-- calculate this row's width and height
		for colNum = 1, Tooltips.NUM_COLUMNS do
			colName = rowName.."Col"..colNum.."Text"
			local x, y = LabelGetTextDimensions( colName )
			local colX, colY = WindowGetDimensions( colName )

			if( x > 0 ) then
				rowWidth = rowWidth + x
			else
				bothColumns = false
			end
			
			rowHeight = math.max(y, rowHeight)
		end
        
        --Debug.PrintToDebugConsole(L"Tooltip ( Row "..rowNum..L" height = "..rowHeight )
		-- if the row's current height isn't what it should be, fix it
		if( rowHeight ~= rowY ) then
			WindowSetDimensions( rowName, rowX, rowHeight )
		end

		-- remember this row's width if it's the widest one we've processed
		if( rowWidth > newWidth ) then
			newWidth = rowWidth
			if( bothColumns == true ) then
				newWidth = newWidth + 10
			end
		end

		newHeight = newHeight + rowHeight
		
        if( rowHeight > 0 ) then
            numRows = numRows + 1
        end
	end

	newHeight = newHeight + Tooltips.BORDER_SIZE
		
	if( numRows > 1 ) then
	    newHeight = newHeight + Tooltips.ROW_SPACING*(numRows-1)
	end
		
	newWidth = newWidth + Tooltips.BORDER_SIZE * 2

	WindowSetDimensions( currentTooltipWindow, newWidth, newHeight )	
	--TextLogAddEntry( "Chat", 100, L"Setting tooltip dimensions to "..newWidth..L", "..newHeight)
end