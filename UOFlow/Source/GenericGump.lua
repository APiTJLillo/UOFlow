----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

GenericGump = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
 
GenericGump.LastGump = ""
GenericGump.LastGumpLabels = {}
GenericGump.GumpsList = {}
 
----------------------------------------------------------------
-- GenericGump Functions
----------------------------------------------------------------

function GenericGump.Initialize()
	local windowName = SystemData.ActiveWindow.name
	Interface.DestroyWindowOnClose[windowName] = true
	GenericGump.LastGump = windowName
	GenericGump.LastGumpLabels = {}	
end

function GenericGump.OnLabelInit()
	local windowName = SystemData.ActiveWindow.name

	local tv ={windowName=windowName}
	table.insert(GenericGump.LastGumpLabels, tv)
end

function GenericGump.Shutdown()	
	local windowName = SystemData.ActiveWindow.name
	local gumpID = GenericGump.GumpsList[windowName]	
	if gumpID then		
		GumpsParsing.ParsedGumps[gumpID] = nil
		GumpsParsing.ToShow[gumpID] = nil
		GumpData.Gumps[gumpID] = nil
	end
	GenericGump.GumpsList[windowName] = nil
end

function GenericGump.OnClicked()
    local gumpId = WindowGetId(SystemData.ActiveWindow.name)
    local windowName = SystemData.ActiveWindow.name
    
    GenericGumpOnClicked(gumpId, windowName)
end

function GenericGump.OnDoubleClicked()
    local gumpId = WindowGetId(SystemData.ActiveWindow.name)
    local windowName = SystemData.ActiveWindow.name
    
    GenericGumpOnDoubleClicked(gumpId, windowName)
end

function GenericGump.OnRClicked()
    local gumpId = WindowGetId(SystemData.ActiveWindow.name)
    
    GenericGumpOnRClicked(gumpId)    
end

function GenericGump.OnMouseOver()
	local gumpId = WindowGetId(SystemData.ActiveWindow.name)
    local windowName = SystemData.ActiveWindow.name
    local dialog = WindowUtils.GetActiveDialog()
    
    if Interface.DebugMode then
		Debug.Print(windowName)
	end
	
    tooltipText = GenericGumpGetToolTipText(gumpId, windowName)
    
    if( tooltipText ~= nil and tooltipText ~= L"" ) then
		Tooltips.CreateTextOnlyTooltip(windowName, tooltipText)
		Tooltips.Finalize()
		Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
	else
		--Debug.Print(L"Tooltip data was nil")
    end
    
    
	objectId = GenericGumpGetItemPropertiesId(gumpId, windowName)
    
    
    if( objectId ~= nil and objectId ~= 0 ) then
		    local itemData = { windowName = dialog,
						       itemId = objectId,
		    			       itemType = WindowData.ItemProperties.TYPE_ITEM,
		    			       detail = ItemProperties.DETAIL_LONG }
		    ItemProperties.SetActiveItem(itemData)      
	
    end
    
end

function GenericGump.OnHyperLinkClicked(link)
    OpenWebBrowser(WStringToString(link))
end
