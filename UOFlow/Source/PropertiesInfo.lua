
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

PropertiesInfo = {}

PropertiesInfo.Items = {}

PropertiesInfo.ITEMPROPERTY_OFFSET =  5000
PropertiesInfo.ITEMPROPICON = 3015

PropertiesInfo.TotalItems = 0

PropertiesInfo.InSearch = false



function PropertiesInfo.Initialize()
	local windowName = "PropertiesInfoWindow"
	SnapUtils.SnappableWindows[windowName] = true
	WindowUtils.RestoreWindowPosition("PropertiesInfoWindow")
	LabelSetText(windowName .. "InfoText", GetStringFromTid(1154921))
	
end

function PropertiesInfo.Shutdown()
	WindowUtils.SaveWindowPosition("PropertiesInfoWindow")
	SnapUtils.SnappableWindows["PropertiesInfoWindow"] = nil
	PropertiesInfo.Close()
end

function PropertiesInfo.Close()
	PropertiesInfo.Reset()
	WindowSetShowing("PropertiesInfoWindow", false)
end

function PropertiesInfo.Toggle()
	if(WindowGetShowing("PropertiesInfoWindow")) then
		PropertiesInfo.Close()
	else
		WindowSetShowing("PropertiesInfoWindow", true)
		PropertiesInfo.Restart()
	end
end


function PropertiesInfo.ClearItemList()
	for i = PropertiesInfo.TotalItems, 1, -1  do
		local dialog = "PropertiesInfoSW"
		local parent = dialog.. "ScrollChild"
		local slotName = parent.."Item"..i
		if DoesWindowNameExist(slotName) then
			DestroyWindow(slotName)
		end
	end
end

function PropertiesInfo.Reset()
	
	PropertiesInfo.ClearItemList()
	PropertiesInfo.Items = {}
	PropertiesInfo.TotalItems = 0
	PropertiesInfo.InSearch = false
	TextEditBoxSetText("PropertiesInfoWindowSearchBox", L"")
	LabelSetText("PropertiesInfoWindowTotal", L"" )
	ScrollWindowUpdateScrollRect( "PropertiesInfoSW" )   	
	local listOffset = ScrollWindowGetOffset("PropertiesInfoSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("PropertiesInfoSWScrollbar")
	if( listOffset > maxOffset ) then
		listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("PropertiesInfoSW",listOffset)
	
end


function PropertiesInfo.OnLButtonUpSearch()
	PropertiesInfo.SearchText(nil, TextEditBoxGetText("PropertiesInfoWindowSearchBox"))
end

function PropertiesInfo.SearchTooltip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1154641))
	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function PropertiesInfo.OnLButtonUpSearch()
	PropertiesInfo.SearchText(nil, TextEditBoxGetText("PropertiesInfoWindowSearchBox"))
end

function PropertiesInfo.RemoveFiltersTooltip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1154792))

	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end


function PropertiesInfo.MoreInfoOnMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1154921))
	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function PropertiesInfo.SearchText(null, text)
	
	if (not text or text == "" or text == L"") then
		return
	end
	text = wstring.lower(text)
	PropertiesInfo.InSearch = true
	PropertiesInfo.ClearItemList()
	
	local numTotalItemProps = CSVUtilities.getNumRows(WindowData.PlayerItemPropCSV)
	local tabelIdx = 1
	local dialog = "PropertiesInfoSW"
	local parent = dialog.. "ScrollChild"
	for i=1,numTotalItemProps do
	
		local tid = WindowData.PlayerItemPropCSV[i].TID	
		local name = PropertiesInfo.RemoveAfterSymbol(GetStringUpppercaseFromTid(tid),"~")
		if wstring.find(wstring.lower(name), text) then
		
			local slotName = parent.."Item"..tabelIdx
			local elementIcon = parent.."Item"..tabelIdx.."Icon"
			local elementName = parent.."Item"..tabelIdx.."Name"
			CreateWindowFromTemplate(slotName, "ItemTemplatePR", parent)
			
			if tabelIdx == 1 then
				WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
				WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			else
				WindowAddAnchor(slotName, "bottomleft", parent.."Item"..tabelIdx-1, "topleft", 0, 0)
				WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			end
			
			local currentPropIdx = i
			local itemPropId = currentPropIdx + PropertiesInfo.ITEMPROPERTY_OFFSET
				
			if(tid == 0)then		
				continue
			end				
			local iconTexture, x, y = GetIconData(PropertiesInfo.ITEMPROPICON)
			DynamicImageSetTexture(elementIcon, iconTexture, x, y)
			DynamicImageSetTextureScale(elementIcon, 0.68)
			
			WindowSetShowing(slotName.."Disabled", false)
			
			LabelSetText(elementName, name)
			
			WindowSetId(slotName,itemPropId)
			WindowSetId(elementIcon, itemPropId)
			tabelIdx = tabelIdx + 1
		end
	end
	PropertiesInfo.TotalItems = tabelIdx - 1
	LabelSetText("PropertiesInfoWindowTotal", ReplaceTokens(GetStringFromTid(1154922), {towstring( tabelIdx - 1)}) )
	ScrollWindowUpdateScrollRect( "PropertiesInfoSW" )   	
	local listOffset = ScrollWindowGetOffset("PropertiesInfoSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("PropertiesInfoSWScrollbar")
	if( listOffset > maxOffset ) then
	    listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("PropertiesInfoSW",listOffset)
end

function PropertiesInfo.RemoveAfterSymbol(currentString,symbol)
	local text = nil
	text = wstring.find(currentString,towstring(symbol))
	if ( text ~= nil ) then							
		text = text - 1
		currentString = wstring.sub(currentString,1,text)		
		text = nil
	end
	return currentString
end

function PropertiesInfo.Restart()
	PropertiesInfo.Reset()
	PropertiesInfo.Items = ItemProperties.GetActiveProperties()
	
	local tabelIdx = 1
	local dialog = "PropertiesInfoSW"
	local parent = dialog.. "ScrollChild"
	for i,k in pairs(PropertiesInfo.Items) do
		local slotName = parent.."Item"..tabelIdx
		local elementIcon = parent.."Item"..tabelIdx.."Icon"
		local elementName = parent.."Item"..tabelIdx.."Name"
		CreateWindowFromTemplate(slotName, "ItemTemplatePR", parent)
		
		if tabelIdx == 1 then
			WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
			WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
		else
			WindowAddAnchor(slotName, "bottomleft", parent.."Item"..tabelIdx-1, "topleft", 0, 0)
			WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
		end
		
		local currentPropIdx = i
		local itemPropId = currentPropIdx + PropertiesInfo.ITEMPROPERTY_OFFSET
		local tid = WindowData.PlayerItemPropCSV[currentPropIdx].TID		
		if(tid == 0)then		
			continue
		end				
		local iconTexture, x, y = GetIconData(PropertiesInfo.ITEMPROPICON)
		DynamicImageSetTexture(elementIcon, iconTexture, x, y)
		DynamicImageSetTextureScale(elementIcon, 0.68)
		
		WindowSetShowing(slotName.."Disabled", false)
		
		
		LabelSetText(elementName, PropertiesInfo.RemoveAfterSymbol(GetStringUpppercaseFromTid(tid),"~"))
		
		WindowSetId(slotName,itemPropId)
		WindowSetId(elementIcon, itemPropId)
		tabelIdx = tabelIdx + 1
	end
	PropertiesInfo.TotalItems = tabelIdx - 1

	local numTotalItemProps = CSVUtilities.getNumRows(WindowData.PlayerItemPropCSV)
	for i=1,numTotalItemProps do
		if not PropertiesInfo.Items[i] then
			local slotName = parent.."Item"..tabelIdx
			local elementIcon = parent.."Item"..tabelIdx.."Icon"
			local elementName = parent.."Item"..tabelIdx.."Name"
			CreateWindowFromTemplate(slotName, "ItemTemplatePR", parent)
			
			if tabelIdx == 1 then
				WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
				WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			else
				WindowAddAnchor(slotName, "bottomleft", parent.."Item"..tabelIdx-1, "topleft", 0, 0)
				WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			end
			
			local currentPropIdx = i
			local itemPropId = currentPropIdx + PropertiesInfo.ITEMPROPERTY_OFFSET
			local tid = WindowData.PlayerItemPropCSV[currentPropIdx].TID		
			if(tid == 0)then		
				continue
			end				
			local iconTexture, x, y = GetIconData(PropertiesInfo.ITEMPROPICON)
			DynamicImageSetTexture(elementIcon, iconTexture, x, y)
			DynamicImageSetTextureScale(elementIcon, 0.68)
			
			LabelSetText(elementName, PropertiesInfo.RemoveAfterSymbol(GetStringUpppercaseFromTid(tid),"~"))
			
			WindowSetShowing(slotName.."Disabled", true)
			
			WindowSetId(slotName,itemPropId)
			WindowSetId(elementIcon, itemPropId)
			tabelIdx = tabelIdx + 1
		end
	end
	


	LabelSetText("PropertiesInfoWindowTotal", ReplaceTokens(GetStringFromTid(1154923), {towstring( PropertiesInfo.TotalItems)}) )
	ScrollWindowUpdateScrollRect( "PropertiesInfoSW" )   	
	local listOffset = ScrollWindowGetOffset("PropertiesInfoSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("PropertiesInfoSWScrollbar")
	if( listOffset > maxOffset ) then
	    listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("PropertiesInfoSW",listOffset)
end


function PropertiesInfo.ItemMouseOver()
	local this = SystemData.ActiveWindow.name
	local id = WindowGetId(SystemData.ActiveWindow.name)
	local elementName = this.."Name"
	elementName = string.gsub(elementName, "Icon", "")
	local descriptionStr = GetStringFromTid(WindowData.PlayerItemPropCSV[id - PropertiesInfo.ITEMPROPERTY_OFFSET].DescriptionTID)
--Debug.Print(WindowData.PlayerItemPropCSV[id - PropertiesInfo.ITEMPROPERTY_OFFSET].DescriptionTID)
	itemData = { windowName = this,
						itemId = id,
						itemType = WindowData.ItemProperties.TYPE_WSTRINGDATA,
						title =	LabelGetText(elementName),
						body = descriptionStr}
						
	ItemProperties.SetActiveItem(itemData)	
end