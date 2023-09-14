
----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ContainerSearch = {}

ContainerSearch.Container = 0
ContainerSearch.Items = {}
ContainerSearch.SearchResult = {}
ContainerSearch.Patterns = {}
ContainerSearch.TotalItems = 0
ContainerSearch.MaxItems = 0

ContainerSearch.Slots = {} 

function ContainerSearch.Initialize()
	local windowName = "ContainerSearchWindow"
	SnapUtils.SnappableWindows[windowName] = true
	WindowUtils.RestoreWindowPosition("ContainerSearchWindow")
	LabelSetText(windowName .. "InfoText", GetStringFromTid(1154791))
	
end

function ContainerSearch.Shutdown()
	WindowUtils.SaveWindowPosition("ContainerSearchWindow")
	SnapUtils.SnappableWindows["ContainerSearchWindow"] = nil
	ContainerSearch.Close()
end

function ContainerSearch.Close()
	ItemProperties.ClearMouseOverItem()
	ContainerSearch.Reset()
	WindowSetShowing("ContainerSearchWindow", false)
end

function ContainerSearch.Toggle()
	if(WindowGetShowing("ContainerSearchWindow")) then
		ContainerSearch.Close()
	else
		WindowSetShowing("ContainerSearchWindow", true)
		ContainerSearch.Restart()
	end
end


function ContainerSearch.ClearItemList()
	for i = 1, #ContainerSearch.Slots  do
		if DoesWindowNameExist(ContainerSearch.Slots[i]) then
			DestroyWindow(ContainerSearch.Slots[i])
		end
	end
	ContainerSearch.Slots = {}
end

function ContainerSearch.Reset()
	ContainerSearch.ClearItemList()
	ContainerSearch.Container = 0
	ContainerSearch.Items = {}
	ContainerSearch.SearchResult = {}
	ContainerSearch.Patterns = {}
	ContainerSearch.TotalItems = 0
	ContainerSearch.MaxItems = 0
	
	LabelSetText("ContainerSearchWindowTotal", L"" )
	ScrollWindowUpdateScrollRect( "ContainerSearchSW" )   	
	local listOffset = ScrollWindowGetOffset("ContainerSearchSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("ContainerSearchSWScrollbar")
	if( listOffset > maxOffset ) then
		listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("ContainerSearchSW",listOffset)
end


function ContainerSearch.OnLButtonUpSearch()
	ContainerSearch.SearchText(nil, TextEditBoxGetText("ContainerSearchWindowSearchBox"))
end

function ContainerSearch.SearchTooltip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1154641))	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function ContainerSearch.OnLButtonUpSearch()
	ContainerSearch.SearchText(nil, TextEditBoxGetText("ContainerSearchWindowSearchBox"))
end

function ContainerSearch.RemoveFiltersTooltip()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1154792))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function ContainerSearch.Tooltip()	
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(3000173))	
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function ContainerSearch.SearchText(null, text)
	if (not text or text == L"" or text == "") then
		return
	end
	local AllItems = ContainerSearch.ScanQuantities(ContainerSearch.Container)
	text = wstring.lower(text)
	local ok = true
	for k = 1, table.getn(ContainerSearch.Patterns) do
		if text == ContainerSearch.Patterns[k] then
			ok = false
			break
		end
	end
	if ok then
		table.insert(ContainerSearch.Patterns, text)
		--Debug.Print(L"ADD " .. text)
	end
	
	local lastlink = 0
	ContainerSearch.ClearItemList()
	--local numItems = WindowData.ContainerWindow[ContainerSearch.Container ].numItems
	ContainerSearch.SearchResult = {}
	ContainerSearch.TotalItems = 0
	for i = 1, #AllItems  do
		local item = {objectId = AllItems[i]} --WindowData.ContainerWindow[ContainerSearch.Container].ContainedItems[i]
		RegisterWindowData(WindowData.ObjectInfo.Type, item.objectId)
		local itemData = WindowData.ObjectInfo[item.objectId]
		if(itemData) then
			local prop = ItemProperties.GetObjectProperties( item.objectId, nil, "Container search - check properties" )
			local color ={}
			local font = {}
			local found = true
			if prop then
				--prop, color, font = ItemProperties.ItemParsing(prop)
				for k = 1, table.getn(ContainerSearch.Patterns) do
					text = ContainerSearch.Patterns[k]
					
					local currentPat = false
					for j = 1, table.getn(prop) do
						
						if (prop[j] and prop[j] ~= "" and prop[j] ~= L"") then
						
						
							prop[j] = wstring.lower(prop[j])
							if j == 1 then
								prop[j] = Shopkeeper.stripFirstNumber(prop[j])
							end
							
							local m_start = wstring.find(text, L"\"")
							local m_end
							if m_start then
								m_end =  wstring.find(text, L"\"", m_start + 1)
							end
							if m_start and m_end then
								text = wstring.sub(text, m_start+1, m_end-1)
								if prop[j] == text then
									currentPat = true
									break
								end
							elseif prop[j] == text or wstring.find(prop[j], text) then
								currentPat = true
								break
							end
						end
					end
					if not currentPat then	
						found = false
					end
				end
			end
			
			if not found then
				continue
			end		
			ContainerSearch.SearchResult[item.objectId] = true
			local dialog = "ContainerSearchSW"
			local parent = dialog.. "ScrollChild"
			local slotName = parent.."Item"..i
			local elementIcon = parent.."Item"..i.."Icon"
			local elementName = parent.."Item"..i.."Name"
			
			CreateWindowFromTemplate(slotName, "ItemTemplate", parent)
			table.insert(ContainerSearch.Slots, slotName)
			WindowSetId(slotName,item.objectId)
			WindowSetId(slotName.."Icon", item.objectId)
			EquipmentData.UpdateItemIcon(elementIcon, itemData)
			if i == 1 or lastlink == 0 then
				WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
				WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			else
				WindowAddAnchor(slotName, "bottomleft", lastlink, "topleft", 0, 0)
				WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			end
			LabelSetText(elementName, itemData.name)
			lastlink = slotName
			ContainerSearch.TotalItems = ContainerSearch.TotalItems +1
		end
		UnregisterWindowData(WindowData.ObjectInfo.Type, item.objectId)
	end
	LabelSetText("ContainerSearchWindowTotal", ReplaceTokens(GetStringFromTid(1154793), {ContainerSearch.TotalItems})  )
	ScrollWindowUpdateScrollRect( "ContainerSearchSW" )   	
	local listOffset = ScrollWindowGetOffset("ContainerSearchSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("ContainerSearchSWScrollbar")
	if( listOffset > maxOffset ) then
		listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("ContainerSearchSW",listOffset)
end

function ContainerSearch.UpdateList(remove)
	local lastlink = 0
	local AllItems = ContainerSearch.ScanQuantities(ContainerSearch.Container)
	ContainerSearch.ClearItemList()
	--local numItems = WindowData.ContainerWindow[ContainerSearch.Container ].numItems
	ContainerSearch.TotalItems = 0
	local toremove = {}
	if(AllItems~= nil)then
		for key, value in pairs(ContainerSearch.SearchResult) do
			local found = false
			for i = 1, #AllItems  do
				local item = {objectId = AllItems[i]} --WindowData.ContainerWindow[ContainerSearch.Container].ContainedItems[i]
				if item.objectId == key then
					found = true
					break
				end
			end
			if not found then
				table.insert(toremove, key)
			end
		end
	end
	for i = 1, table.getn(toremove) do
		ContainerSearch.SearchResult[toremove[i]] = nil
	end
	lastlink = 0
	local i = 1
	for key, value in pairs(ContainerSearch.SearchResult) do
		
		if value then
			RegisterWindowData(WindowData.ObjectInfo.Type, key)
			local itemData = WindowData.ObjectInfo[key]
			if(itemData) then			
				
				local dialog = "ContainerSearchSW"
				local parent = dialog.. "ScrollChild"
				local slotName = parent.."Item"..i
				local elementIcon = parent.."Item"..i.."Icon"
				local elementName = parent.."Item"..i.."Name"
				
				CreateWindowFromTemplate(slotName, "ItemTemplate", parent)
				table.insert(ContainerSearch.Slots, slotName)
				WindowSetId(slotName,key)
				WindowSetId(slotName.."Icon", key)
				EquipmentData.UpdateItemIcon(elementIcon, itemData)
				if i == 1 or lastlink == 0 then
					WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
					WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
				else
					WindowAddAnchor(slotName, "bottomleft", lastlink, "topleft", 0, 0)
					WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
				end
				LabelSetText(elementName, itemData.name)
				lastlink = slotName
				ContainerSearch.TotalItems = ContainerSearch.TotalItems +1
			end
			UnregisterWindowData(WindowData.ObjectInfo.Type, key)
			i = i + 1
		end
	end
	LabelSetText("ContainerSearchWindowTotal", L"Total Items: " .. ContainerSearch.TotalItems )
	ScrollWindowUpdateScrollRect( "ContainerSearchSW" )   	
	local listOffset = ScrollWindowGetOffset("ContainerSearchSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("ContainerSearchSWScrollbar")
	if( listOffset > maxOffset ) then
		listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("ContainerSearchSW",listOffset)
end


function ContainerSearch.Restart()
	if (not ContainerSearch.Container) then
		return
	end
	local AllItems = ContainerSearch.ScanQuantities(ContainerSearch.Container)
	ContainerSearch.Patterns = {}
	ContainerSearch.SearchResult = {}
	TextEditBoxSetText("ContainerSearchWindowSearchBox", L"")
	ContainerSearch.ClearItemList()
	local objectId = ContainerSearch.Container
	ContainerSearch.Items = table.copy(AllItems)
	local numItems = WindowData.ContainerWindow[objectId].numItems
	local lastlink = ""
	for i = 1, #AllItems  do
		local item = {objectId = AllItems[i]} --WindowData.ContainerWindow[ContainerSearch.Container].ContainedItems[i]
		RegisterWindowData(WindowData.ObjectInfo.Type, item.objectId)
		local itemData = WindowData.ObjectInfo[item.objectId]
		if(itemData) then
			ContainerSearch.SearchResult[item.objectId] = true
			local dialog = "ContainerSearchSW"
			local parent = dialog.. "ScrollChild"
			local slotName = parent.."Item"..i
			local elementIcon = parent.."Item"..i.."Icon"
			local elementName = parent.."Item"..i.."Name"
			
			CreateWindowFromTemplate(slotName, "ItemTemplate", parent)
			table.insert(ContainerSearch.Slots, slotName)
			WindowSetId(slotName,item.objectId)
			WindowSetId(slotName.."Icon", item.objectId)
	        EquipmentData.UpdateItemIcon(elementIcon, itemData)
			if i == 1 then
				WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 5)
				WindowAddAnchor(slotName, "topright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			else
				WindowAddAnchor(slotName, "bottomleft", lastlink, "topleft", 0, 0)
				WindowAddAnchor(slotName, "bottomright", dialog, "topright", -ContainerWindow.List.LabelPaddingRight, 0)
			end
			lastlink = slotName
			LabelSetText(elementName, itemData.name)
		end
		UnregisterWindowData(WindowData.ObjectInfo.Type, item.objectId)
	end
	ContainerSearch.TotalItems = #AllItems
	ContainerSearch.MaxItems = ContainerSearch.TotalItems
	LabelSetText("ContainerSearchWindowTotal", L"Total Items: " .. ContainerSearch.TotalItems )
	ScrollWindowUpdateScrollRect( "ContainerSearchSW" )   	
	local listOffset = ScrollWindowGetOffset("ContainerSearchSW")
	local maxOffset = VerticalScrollbarGetMaxScrollPosition("ContainerSearchSWScrollbar")
	if( listOffset > maxOffset ) then
	    listOffset = maxOffset
	end
	
	ScrollWindowSetOffset("ContainerSearchSW",listOffset)
end

function ContainerSearch.OnItemClicked()
	local this = SystemData.ActiveWindow.name
	local dialog = WindowUtils.GetActiveDialog()
	local objectId = WindowGetId(this)

	if (objectId) then
	    if( WindowData.Cursor ~= nil and WindowData.Cursor.target == true ) then
			HandleSingleLeftClkTarget(objectId)
	    elseif( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_NONE ) then
			DragSlotSetObjectMouseClickData(objectId, SystemData.DragSource.SOURCETYPE_CONTAINER)
			ContainerSearch.UpdateList(objectId)
	    end
	end
	
end
function ContainerSearch.ItemMouseOver()
	local this = SystemData.ActiveWindow.name
	local dialog = WindowUtils.GetActiveDialog()
	local id = WindowGetId(this)
	if (id) then
	    local itemData = { windowName = dialog,
					       itemId = id,
	    			       itemType = WindowData.ItemProperties.TYPE_ITEM,
	    			       detail = ItemProperties.DETAIL_LONG }
	    ItemProperties.SetActiveItem(itemData)
	end
end

function ContainerSearch.ScanSubCont(id, allItems)
	local legacyContainersMode = SystemData.Settings.Interface.LegacyContainers
	if(legacyContainersMode)then		
		return allItems
	end

	local removeOnComplete = false
	if not WindowData.ContainerWindow[id] then
		removeOnComplete = true
		RegisterWindowData(WindowData.ContainerWindow.Type, id)
	end

	if WindowData.ContainerWindow[id] then		
		local numItems = WindowData.ContainerWindow[id].numItems
		for i = 1, numItems do
			local item = WindowData.ContainerWindow[id].ContainedItems[i]
			allItems = ContainerSearch.ScanSubCont(item.objectId, allItems)
			table.insert(allItems,item.objectId )			
		end
	end

	if(ContainerWindow.OpenContainers[id] == nil and removeOnComplete)then		
		UnregisterWindowData(WindowData.ContainerWindow.Type, id)
	end
	return allItems
end

function ContainerSearch.ScanQuantities(backpackId)
	local legacyContainersMode = SystemData.Settings.Interface.LegacyContainers
	if(legacyContainersMode)then
		return
	end
	local AllItems = {}
	local removeOnComplete = false 
	if not WindowData.ContainerWindow[backpackId] then
		removeOnComplete = true		
		RegisterWindowData(WindowData.ContainerWindow.Type, backpackId)
	end
	local numItems = WindowData.ContainerWindow[backpackId].numItems
	for i = 1, numItems do
		local item = WindowData.ContainerWindow[backpackId].ContainedItems[i]
		AllItems = ContainerSearch.ScanSubCont(item.objectId, AllItems)
		table.insert(AllItems,item.objectId )
	end
	if(ContainerWindow.OpenContainers[backpackId] == nil and removeOnComplete)then
		UnregisterWindowData(WindowData.ContainerWindow.Type, backpackId)
	end
	return AllItems
end