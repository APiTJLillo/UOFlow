----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ChatFontWindow = {}

ChatFontWindow.TID = { ChatFont=1111686,Close=1052061 }

-- OnInitialize Handler
function ChatFontWindow.Initialize()
	local wndNum = ChatWindow.GetCurrentTabID()
    WindowUtils.SetWindowTitle("ChatFontWindow", GetStringFromTid(ChatFontWindow.TID.ChatFont) )
    ButtonSetText( "ChatFontWindowAcceptButton", GetStringFromTid(ChatFontWindow.TID.Close) ) 
    
    Interface.DestroyWindowOnClose["ChatFontWindow"] = true
    
	Debug.Print("Active font: "..LogDisplayGetFont(ChatWindow.Windows[wndNum].Tabs[1].tabWindow))
    
    local size = #ChatSettings.Fonts
    for idx=1, size do
		local itemWindow = "ChatFontWindowItem"..idx
        CreateWindowFromTemplate (itemWindow, "ChatFontRowTemplate", "ChatFontWindow")
        LabelSetFont( itemWindow.."Label", ChatSettings.Fonts[idx].fontName, WindowUtils.FONT_DEFAULT_TEXT_LINESPACING )
        LabelSetText( itemWindow.."Label", StringToWString(ChatSettings.Fonts[idx].shownName) )
        WindowSetId(itemWindow, idx)
        
        if (LogDisplayGetFont(ChatWindow.Windows[wndNum].Tabs[1].tabWindow) == ChatSettings.Fonts[idx].fontName)
        then
			 Debug.Print("Show Check: "..tostring(idx))
             WindowSetShowing(itemWindow.."Check", true)
        else
             WindowSetShowing(itemWindow.."Check", false)
        end
        
        if( idx == 1 ) then
			WindowAddAnchor( itemWindow, "topleft", "ChatFontWindow", "topleft", 20, 40 )
        else
			WindowAddAnchor( itemWindow, "bottomleft", "ChatFontWindowItem"..(idx-1), "topleft", 0, 0 )
        end
    end
end


function ChatFontWindow.Shutdown()
    
end

function ChatFontWindow.SetFontToSelection()
    local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
    local wndNum = ChatWindow.GetCurrentTabID()
    local tab = ChatWindow.Windows[wndNum].Tabs[1]

    local size = #ChatSettings.Fonts
    for idx=1, size do
		local itemWindow = "ChatFontWindowItem"..idx
		WindowSetShowing(itemWindow.."Check", false)
	end
	
    WindowSetShowing(SystemData.ActiveWindow.name.."Check", true)
    LogDisplaySetFont(tab.tabWindow, ChatSettings.Fonts[fontIndex].fontName)
    bDirty = true
end

function ChatFontWindow.CloseFontWindow()
	DestroyWindow("ChatFontWindow")
end

function ChatFontWindow.ItemMouseOver()
	local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
	local itemWindow = "ChatFontWindowItem"..fontIndex
	
	LabelSetTextColor(itemWindow.."Label",243,227,49)
end

function ChatFontWindow.ClearMouseOverItem()
	local fontIndex = WindowGetId(SystemData.ActiveWindow.name)
	local itemWindow = "ChatFontWindowItem"..fontIndex
	
	LabelSetTextColor(itemWindow.."Label",255,255,255)
end