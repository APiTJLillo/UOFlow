----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

FontSelector = {}

local function Font( iname, iid, idefault, ishownName )
    local newChannel = 
    {
        fontName         = iname,
        id           = iid,
        isDefault    = idefault,
        shownName    = ishownName,
    };

    return newChannel;
end

FontSelector.Selection = ""
FontSelector.RunicFontItem = ""

 FontSelector.Fonts = {}
 --                               name of font     id  default  name to be shown
FontSelector.Fonts[1] = Font( "UO_Overhead_Chat", 1, true, "Default" )
FontSelector.Fonts[2] = Font( "UO_NeueText", 1, false, "Neue Text" )
FontSelector.Fonts[3] = Font( "UO_DefaultText_15pt", 1, false, "MyriadPro" )
FontSelector.Fonts[4] = Font( "UO_Runic_20pt", 1, false, "Runic Font" )
FontSelector.Fonts[5] = Font( "UO_Gargish_20pt", 1, false, "Gargish" )

-- OnInitialize Handler
function FontSelector.Initialize()    
    --WindowSetScale("FontSelector", 1.28)
    Interface.DestroyWindowOnClose["FontSelector"] = true    
    local size = #FontSelector.Fonts
    for idx=1, size do
		local itemWindow = "FontSelectorItem"..idx
		if DoesWindowNameExist( itemWindow) then
			DestroyWindow(itemWindow)
		end
		CreateWindowFromTemplate (itemWindow, "FontRowTemplate", "FontSelector")
		LabelSetFont( itemWindow.."Label", FontSelector.Fonts[idx].fontName, WindowUtils.FONT_DEFAULT_TEXT_LINESPACING )
		LabelSetText( itemWindow.."Label", StringToWString(FontSelector.Fonts[idx].shownName) )
		local x, y = WindowGetDimensions(itemWindow.."Label")
		WindowSetDimensions(itemWindow, x, y)
		WindowSetId(itemWindow, idx)
		WindowClearAnchors(itemWindow)		
		WindowSetShowing(itemWindow.."Check", false)		
		local attachIndex = idx -1
		if (FontSelector.Fonts[idx].fontName == "UO_Runic_20pt" ) then
			FontSelector.RunicFontItem = itemWindow
		end		
		if (FontSelector.Fonts[idx].fontName == "gargrunic" ) then
				attachIndex = idx - 2
		end		
	    	    
	    if (attachIndex<=0) then
			attachIndex = 1
	    end
	    
		if( idx == 1 ) then
			WindowAddAnchor( itemWindow, "topleft", "FontSelector", "topleft", 20, 40 )
		else
			WindowAddAnchor( itemWindow, "bottomleft", "FontSelectorItem"..attachIndex, "topleft", 0, 7 )			
		end    
   end   
end

function FontSelector.OnShown()
	local selectedIdx = 1
    if (FontSelector.Selection == "chat") then
		selectedIdx = OverheadText.FontIndex 
	elseif (FontSelector.Selection == "names") then
		selectedIdx = OverheadText.NameFontIndex
	elseif (FontSelector.Selection == "spells") then
		selectedIdx = OverheadText.SpellsFontIndex 
	elseif (FontSelector.Selection == "damage") then
		selectedIdx = OverheadText.DamageFontIndex
	elseif (string.find(FontSelector.Selection, "journal")) then
		local id = string.gsub(FontSelector.Selection, "journal", "")
		id = tonumber(id)
		selectedIdx = NewChatWindow.ChannelsFonts[ id ]
	end

	local size = #FontSelector.Fonts
    for idx=1, size do
		local itemWindow = "FontSelectorItem"..idx
		if (selectedIdx == idx) then
			WindowSetShowing(itemWindow.."Check", true)
			WindowClearAnchors(itemWindow.."Check")
			WindowForceProcessAnchors(itemWindow.."Check")
			WindowAddAnchor( itemWindow.."Check", "left", itemWindow.."Label", "center", -17, 0 )
		else
			WindowSetShowing(itemWindow.."Check", false)
		end
	end	
end

function FontSelector.Shutdown()
    DestroyWindow("FontSelector")
end

function FontSelector.SetFontToSelection()
	if (FontSelector.Selection == "chat") then
		OverheadText.FontIndex = WindowGetId(SystemData.ActiveWindow.name)
		Interface.SaveNumber("OverheadTextFontIndex", OverheadText.FontIndex)
		WindowSetShowing("FontSelector", false)
	elseif (FontSelector.Selection == "names") then
		OverheadText.NameFontIndex = WindowGetId(SystemData.ActiveWindow.name)
		Interface.SaveNumber("OverheadTextNameFontIndex", OverheadText.NameFontIndex)
		WindowSetShowing("FontSelector", false)
	elseif (FontSelector.Selection == "spells") then
		OverheadText.SpellsFontIndex = WindowGetId(SystemData.ActiveWindow.name)
		Interface.SaveNumber("OverheadTextSpellsFontIndex", OverheadText.SpellsFontIndex)
		WindowSetShowing("FontSelector", false)
	elseif (FontSelector.Selection == "damage") then
		OverheadText.DamageFontIndex = WindowGetId(SystemData.ActiveWindow.name)
		Interface.SaveNumber("OverheadTextDamageFontIndex", OverheadText.DamageFontIndex)
		WindowSetShowing("FontSelector", false)
	elseif (string.find(FontSelector.Selection, "journal")) then
		local id = string.gsub(FontSelector.Selection, "journal", "")
		id = tonumber(id)
		NewChatWindow.ChannelsFonts[ id ] = WindowGetId(SystemData.ActiveWindow.name)
		Interface.SaveNumber("ChannelsFonts" .. id, NewChatWindow.ChannelsFonts[ id ])
		NewChatWindow.ClearAll()
		NewChatWindow.UpdateLog()
		WindowSetShowing("FontSelector", false)
	end
end

function FontSelector.CloseFontWindow()
	WindowSetShowing("FontSelector", false)
end

function FontSelector.ItemMouseOver()
	local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
	local itemWindow = "FontSelectorItem"..fontIndex	
	LabelSetTextColor(itemWindow.."Label",243,227,49)
end

function FontSelector.ClearMouseOverItem()
	local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
	local itemWindow = "FontSelectorItem"..fontIndex	
	LabelSetTextColor(itemWindow.."Label",255,255,255)
end