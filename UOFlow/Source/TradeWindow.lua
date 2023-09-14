----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

TradeWindow = {}
TradeWindow.TradeInfo ={}
--[[
Variables in TradeInfo:
containerId
containerId2
tradeName
containerIdAccept
containerId2Accept
myTradeGold
myTradePlat
myGoldBalance
myPlatBalance
theirTradeGold
theirTradePlat
]]

TradeWindow.RegisteredItems = {}
TradeWindow.OpenContainers = {}
TradeWindow.NumCreatedSlots = {}

					--My Offer ,Their Offer, Accept, Cancel, Waiting, Accepted, Offer, Trade
TradeWindow.StringText = { 1077713, 3000145, 1013076, 1006045, 1077715, 1077716, 1077714, 1077728 }
----------------------------------------------------------------
-- ContainerWindow Functions
----------------------------------------------------------------
function TradeWindow.OnCloseDialog()
	BroadcastEvent(SystemData.Events.TRADE_SEND_CLOSE_WINDOW)
end

function TradeWindow.Initialize()
	local this = SystemData.ActiveWindow.name
	local id = SystemData.DynamicWindowId
	WindowSetId(this, id)
	
	local title = GetStringFromTid(TradeWindow.StringText[8])
	WindowUtils.SetWindowTitle(this, title)
	
	Interface.DestroyWindowOnClose[this] = true
	Interface.OnCloseCallBack[this] = TradeWindow.OnCloseDialog
	
	--Store the TradeInfo
	TradeWindow.TradeInfo[this] = WindowData.TradeInfo
	TradeWindow.OpenContainers[this] = true
	TradeWindow.NumCreatedSlots[this] = {}
	TradeWindow.NumCreatedSlots[this][TradeWindow.TradeInfo[this].containerId] = 0
	TradeWindow.NumCreatedSlots[this][TradeWindow.TradeInfo[this].containerId2] = 0

	WindowRegisterEventHandler(this, SystemData.Events.TRADE_RECEIVE_CLOSE_WINDOW, "TradeWindow.CloseWindow")
	WindowRegisterEventHandler(this, SystemData.Events.TRADE_RECEIVE_ACCEPTMSG_WINDOW, "TradeWindow.AcceptMessage")
	WindowRegisterEventHandler(this, SystemData.Events.TRADE_RECEIVE_MODIFYGOLD_WINDOW, "TradeWindow.ModifyTheirGold")
	WindowRegisterEventHandler(this, SystemData.Events.TRADE_RECEIVE_BALANCE_WINDOW, "TradeWindow.UpdateBalance")
	
	--Register with two ContainerWindows
	RegisterWindowData(WindowData.ContainerWindow.Type, TradeWindow.TradeInfo[this].containerId)
	RegisterWindowData(WindowData.ContainerWindow.Type, TradeWindow.TradeInfo[this].containerId2)
	WindowRegisterEventHandler(this, WindowData.ContainerWindow.Event, "TradeWindow.MiniModelUpdate")
	WindowRegisterEventHandler(this, WindowData.ObjectInfo.Event, "TradeWindow.HandleUpdateObjectEvent")
	
	local offerString = GetStringFromTid(TradeWindow.StringText[1])
	LabelSetText(this.."ItemDescMyOffer", offerString)
	offerString = GetStringFromTid(TradeWindow.StringText[2])
	LabelSetText(this.."ItemDescTradeOffer", offerString)
	
	local playerName = TradeWindow.TradeInfo[this].playerName
	LabelSetText(this.."PlayerAcceptName", playerName)
	local tradeName = TradeWindow.TradeInfo[this].tradeName
	LabelSetText(this.."TradeAcceptName", StringToWString(tradeName))
	
	local playerButtonName = this.."PlayerAcceptCheck"
	local tradeButtonName = this.."TradeAcceptCheck"
	
	ButtonSetStayDownFlag(playerButtonName, true)
	ButtonSetStayDownFlag(tradeButtonName, true)
				
	TextEditBoxSetText(this.. "PlayerAcceptGoldAmountGold",  L""..0)
	LabelSetText(this.. "PlayerWaitingGoldAmountGold", L""..0)
	LabelSetText(this.. "PlayerAcceptGoldAmountGoldWtihCommas", L""..0)

	TextEditBoxSetText(this.. "PlayerAcceptGoldAmountPlat",  L""..0 )
	LabelSetText(this.. "PlayerWaitingGoldAmountPlat", L""..0)
	LabelSetText(this.. "PlayerAcceptGoldAmountPlatWtihCommas", L""..0)

	TradeWindow.AcceptMessage()

	local textureGold, goldx, goldy = GetIconData( 85843 )
	local texturePlat, platx, platy = GetIconData( 85842 )
	
	DynamicImageSetTextureDimensions(this.. "PlayerAcceptGoldImageGold", 40, 30)
	WindowSetDimensions(this.. "PlayerAcceptGoldImageGold", 40, 30)
	DynamicImageSetTexture(this.. "PlayerAcceptGoldImageGold", textureGold, goldx, goldy )
	DynamicImageSetTextureScale(this.. "PlayerAcceptGoldImageGold", 1)

	DynamicImageSetTextureDimensions(this.. "PlayerAcceptGoldImagePlat", 40, 30)
	WindowSetDimensions(this.. "PlayerAcceptGoldImagePlat", 40, 30)
	DynamicImageSetTexture(this.. "PlayerAcceptGoldImagePlat", texturePlat, platx, platy)
	DynamicImageSetTextureScale(this.. "PlayerAcceptGoldImagePlat", 1)

	DynamicImageSetTextureDimensions(this.. "PlayerWaitingGoldImageGold", 40, 30)
	WindowSetDimensions(this.. "PlayerWaitingGoldImageGold", 40, 30)
	DynamicImageSetTexture(this.. "PlayerWaitingGoldImageGold", textureGold, goldx, goldy )
	DynamicImageSetTextureScale(this.. "PlayerWaitingGoldImageGold", 1)

	DynamicImageSetTextureDimensions(this.. "PlayerWaitingGoldImagePlat", 40, 30)
	WindowSetDimensions(this.. "PlayerWaitingGoldImagePlat", 40, 30)
	DynamicImageSetTexture(this.. "PlayerWaitingGoldImagePlat", texturePlat, platx, platy )
	DynamicImageSetTextureScale(this.. "PlayerWaitingGoldImagePlat", 1)

	DynamicImageSetTextureDimensions(this.. "BalanceDescImageGold", 40, 30)
	WindowSetDimensions(this.. "BalanceDescImageGold", 40, 30)
	DynamicImageSetTexture(this.. "BalanceDescImageGold", textureGold, goldx, goldy )
	DynamicImageSetTextureScale(this.. "BalanceDescImageGold", 1)

	DynamicImageSetTextureDimensions(this.. "BalanceDescImagePlat", 40, 30)
	WindowSetDimensions(this.. "BalanceDescImagePlat", 40, 30)
	DynamicImageSetTexture(this.. "BalanceDescImagePlat", texturePlat, platx, platy )
	DynamicImageSetTextureScale(this.. "BalanceDescImagePlat", 1)

	LabelSetText(this.. "BalanceDescBalanceGold", L""..0)
	LabelSetText(this.. "BalanceDescBalancePlat", L""..0)
	
end

function TradeWindow.UpdateBalance()
		
	local this = SystemData.ActiveWindow.name
	LabelSetText(this.. "BalanceDescBalanceGold", WindowUtils.AddCommasToNumber(WindowData.TradeInfo.myGoldBalance))
	LabelSetText(this.. "BalanceDescBalancePlat", WindowUtils.AddCommasToNumber(WindowData.TradeInfo.myPlatBalance))
end

function TradeWindow.ModifyTheirGold()	
		
	local this = SystemData.ActiveWindow.name
	LabelSetText(this.. "PlayerWaitingGoldAmountGold", WindowUtils.AddCommasToNumber(WindowData.TradeInfo.theirTradeGold))
	LabelSetText(this.. "PlayerWaitingGoldAmountPlat", WindowUtils.AddCommasToNumber(WindowData.TradeInfo.theirTradePlat))
end

function TradeWindow.ReleaseRegisteredInfo()
	local this = SystemData.ActiveWindow.name
	
	if((this ~= nil ) and (TradeWindow.TradeInfo[this] ~= nil)) then
		--Release player container information
		local contId = TradeWindow.TradeInfo[this].containerId
		if(contId ~= nil) then
			TradeWindow.ReleaseRegisteredObjects(this, contId)
			UnregisterWindowData(WindowData.ContainerWindow.Type, contId)
		end
		
		--Release traders container information
		contId = TradeWindow.TradeInfo[this].containerId2
		if(contId ~= nil) then
			TradeWindow.ReleaseRegisteredObjects(this, contId)
			UnregisterWindowData(WindowData.ContainerWindow.Type, contId)
		end
		
		TradeWindow.OpenContainers[this] = {}
		TradeWindow.TradeInfo[this] = {}
		TradeWindow.NumCreatedSlots[this] = {}
	end
end

function TradeWindow.Shutdown()
	ItemProperties.ClearMouseOverItem()
	
	TradeWindow.ReleaseRegisteredInfo()
end

function TradeWindow.ReleaseRegisteredObjects(parentWindow, containerId)
	if( TradeWindow.RegisteredItems[containerId] ~= nil ) then
		for id, value in pairs(TradeWindow.RegisteredItems[containerId]) do
			UnregisterWindowData(WindowData.ObjectInfo.Type, id)
		end
		TradeWindow.RegisteredItems[containerId] = {}
	end
end

function TradeWindow.HideAllContents(parent, amount)
	for i =1, 125 do
		if i <= amount then
			WindowSetShowing(parent..i, false)
		end
	end
end

function TradeWindow.CreateSlots(parentWindow, nextWindow, low, high)
	
	parent = parentWindow..nextWindow.."ScrollWindowScrollChild"
	for i=low, high do
		slotName = parent.."Item"..i
		CreateWindowFromTemplate(slotName, "TradeItemTemplate", parent)
		WindowSetId(slotName,i)
		WindowSetId(slotName.."Icon", i)
		
		if i == 1 then
			WindowAddAnchor(slotName, "topleft", parent, "topleft", 0, 0)
		else
			WindowAddAnchor(slotName, "bottomleft", parent.."Item"..i-1, "topleft", 0, 0)
		end
	end

	ScrollWindowUpdateScrollRect(parentWindow..nextWindow.."ScrollWindow")	
end


function TradeWindow.UpdateContents(contId, win, force)
	local this = SystemData.ActiveWindow.name
	if win then
		this = win
	end
	local contents
	local numItems
	local numCreatedSlots
	local fullName
	local updateFlag = false
	
	local data = {}
	data = WindowData.ContainerWindow[contId]
	if force then
		updateFlag = true
	end

	if (data and TradeWindow.TradeInfo[this] ~= nil ) then
		contents = data.ContainedItems
		numItems = data.numItems

		numCreatedSlots = TradeWindow.NumCreatedSlots[this][contId] or 0
		--If container Id is the players container Id update the players contents otherwise update the trader content
		if( TradeWindow.TradeInfo[this].containerId == contId ) then
			-- Create any contents slots we need for the container	
			fullName = this.."PlayerList"
			if numItems > numCreatedSlots then
				TradeWindow.CreateSlots(this, "PlayerList", numCreatedSlots+1, numItems)
				TradeWindow.NumCreatedSlots[this][contId] = numItems
			end			
			updateFlag = true
		elseif( TradeWindow.TradeInfo[this].containerId2 == contId ) then
			-- Create any contents slots we need for the container
			fullName = this.."TraderList"
			if numItems > numCreatedSlots then
				TradeWindow.CreateSlots(this, "TraderList", numCreatedSlots+1, numItems)
				TradeWindow.NumCreatedSlots[this][contId] = numItems
			end			
			updateFlag = true
		end
		
		if (updateFlag == true) then
			contentName = fullName.."ScrollWindowScrollChildItem"
			-- Turn off all contents to start
			TradeWindow.HideAllContents(contentName, numCreatedSlots)
			--WindowRefreshScrollChild(fullName.."ScrollWindowScrollChild")
			TradeWindow.ReleaseRegisteredObjects(this, contId)
							
			TradeWindow.RegisteredItems[contId] = {}
			local items, qta, wgt = ContainerWindow.ScanQuantities(contId)
			
			for i = 1, numItems do
				item = data.ContainedItems[i]
				TradeWindow.RegisteredItems[contId][item.objectId]= true
				RegisterWindowData(WindowData.ObjectInfo.Type, item.objectId)
				
				-- perform the initial update of this object
				TradeWindow.UpdateObject(this,item.objectId)
				WindowSetShowing(contentName..i,true)
			end
			
			-- Update the scroll windows			
			ScrollWindowUpdateScrollRect( fullName.."ScrollWindow" )
                
		end
	end
end

-------------------------------------------------------------------------
-- Xml event Handlers
------------------------------------------------------------------------

function TradeWindow.DropObjectInContainer(currWindow, playerWindow, parentWindow)
	if( (currWindow == playerWindow) and SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then
		local containerId = TradeWindow.TradeInfo[parentWindow].containerId
		
		DragSlotDropObjectToContainer(containerId,0)
	end
end

function TradeWindow.IsPlayerContainer(currWindow, parentWindow)
	local playerWindow = parentWindow.."PlayerList"
	if (currWindow == playerWindow) then
		return true
	end
	return false
end

function TradeWindow.IsTraderContainer(currWindow, parentWindow)
	local traderWindow = parentWindow.."TraderList"
	if (currWindow == traderWindow) then
		return true
	end
	return false
end

function TradeWindow.OnContainerRelease()
	local this = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(this)
	local playerWindow = parentWindow.."PlayerList"
	TradeWindow.DropObjectInContainer(this, playerWindow, parentWindow)
end


function TradeWindow.OnItemRelease()
	local this = WindowGetParent(SystemData.ActiveWindow.name)
	local currWindow = WindowGetParent(this)
	local nextWindow = WindowGetParent(currWindow)
	local parentWindow = WindowGetParent(nextWindow)
	local playerWindow = parentWindow.."PlayerList"
	TradeWindow.DropObjectInContainer(nextWindow, playerWindow, parentWindow)
end

function TradeWindow.OnItemDblClicked()
	local currWindowId = WindowGetId(SystemData.ActiveWindow.name)
	local this = WindowGetParent(SystemData.ActiveWindow.name)
	local currWindow = WindowGetParent(this)
	local nextWindow = WindowGetParent(currWindow)
	local parentWindow = WindowGetParent(nextWindow)
	local objectId
	
	if(TradeWindow.IsPlayerContainer(nextWindow, parentWindow)) then
		local containerId = TradeWindow.TradeInfo[parentWindow].containerId
		objectId = WindowData.ContainerWindow[containerId].ContainedItems[currWindowId].objectId
	elseif(TradeWindow.IsTraderContainer(nextWindow, parentWindow)) then
		local containerId2 = TradeWindow.TradeInfo[parentWindow].containerId2
		objectId = WindowData.ContainerWindow[containerId2].ContainedItems[currWindowId].objectId
	end
	
	if objectId then
		UserActionUseItem(objectId,false)
	end
end

function TradeWindow.ItemMouseOver()
	local currWindowId = WindowGetId(SystemData.ActiveWindow.name)
	local this = WindowGetParent(SystemData.ActiveWindow.name)
	local currWindow = WindowGetParent(this)
	local nextWindow = WindowGetParent(currWindow)
	local parentWindow = WindowGetParent(nextWindow)
	local objectId
	
	if(TradeWindow.IsPlayerContainer(nextWindow, parentWindow)) then
		local containerId = TradeWindow.TradeInfo[parentWindow].containerId
		objectId = WindowData.ContainerWindow[containerId].ContainedItems[currWindowId].objectId
	elseif(TradeWindow.IsTraderContainer(nextWindow, parentWindow)) then
		local containerId2 = TradeWindow.TradeInfo[parentWindow].containerId2
		objectId = WindowData.ContainerWindow[containerId2].ContainedItems[currWindowId].objectId
	end
	
	if objectId then
		local itemData = { windowName = this,
							itemId = objectId,
							itemType = WindowData.ItemProperties.TYPE_ITEM,
							detail = ItemProperties.DETAIL_LONG }
		ItemProperties.SetActiveItem(itemData)
	end
	
end

function TradeWindow.OnAccept()
	local this = SystemData.ActiveWindow.name
	local nextWindow = WindowGetParent(this)
	local parentWindow = WindowGetParent(nextWindow)

	if(TradeWindow.TradeInfo[parentWindow] == nil) then
		TradeWindow.TradeInfo[parentWindow] = {}
	end
	
	if(TradeWindow.TradeInfo[parentWindow].containerIdAccept) then
		WindowData.TradeInfo.containerIdAccept = false
		TradeWindow.TradeInfo[parentWindow].containerIdAccept = false
	else
		WindowData.TradeInfo.containerIdAccept = true
		TradeWindow.TradeInfo[parentWindow].containerIdAccept = true
	end

	BroadcastEvent(SystemData.Events.TRADE_SEND_ACCEPTMSG_WINDOW)
end

---------------------------------------------------------------------------
-- Event Handlers
---------------------------------------------------------------------------

--Close Window
function TradeWindow.CloseWindow()
	DestroyWindow(SystemData.ActiveWindow.name)
end

--Accept Message
function TradeWindow.AcceptMessage()
	local this = SystemData.ActiveWindow.name
	local playerButtonName = this.."PlayerAcceptCheck"
	local tradeButtonName = this.."TradeAcceptCheck"
	local playerButtonLabel = this.."PlayerAcceptButton"
	local tradeLabel = this.."TradeAcceptLabel"
	local tradeGoldAmount = this.. "PlayerAcceptGoldAmountGold";
	local tradePlatAmount = this.. "PlayerAcceptGoldAmountPlat";
	local stringData	

	if(TradeWindow.TradeInfo[this].containerIdAccept ) then
		ButtonSetPressedFlag(playerButtonName, true)
		stringData = GetStringFromTid(TradeWindow.StringText[4])
		ButtonSetText(playerButtonLabel, stringData)		
	else
		ButtonSetPressedFlag(playerButtonName, false)
		stringData = GetStringFromTid(TradeWindow.StringText[3])
		ButtonSetText(playerButtonLabel, stringData)		
	end
	
	if(TradeWindow.TradeInfo[this].containerId2Accept) then
		ButtonSetPressedFlag(tradeButtonName, true)
		stringData = GetStringFromTid(TradeWindow.StringText[6])
		LabelSetText(tradeLabel, stringData)
	else
		ButtonSetPressedFlag(tradeButtonName, false)
		stringData = GetStringFromTid(TradeWindow.StringText[5])
		LabelSetText(tradeLabel, stringData)
	end

	if TradeWindow.TradeInfo[this].containerIdAccept or TradeWindow.TradeInfo[this].containerId2Accept then
		WindowSetHandleInput(tradeGoldAmount,false);
		WindowSetHandleInput(tradePlatAmount,false);
	else
		WindowSetHandleInput(tradeGoldAmount,true);
		WindowSetHandleInput(tradePlatAmount,true);
	end

end

--Container window changed, update objects in the container window
function TradeWindow.MiniModelUpdate()
	local contId = WindowData.UpdateInstanceId
	local this = SystemData.ActiveWindow.name
	
	if( TradeWindow.TradeInfo[this].containerId == contId or
	    TradeWindow.TradeInfo[this].containerId2 == contId ) then
		TradeWindow.UpdateContents(contId)
	end
end

function TradeWindow.HandleUpdateObjectEvent()
    TradeWindow.UpdateObject(SystemData.ActiveWindow.name,WindowData.UpdateInstanceId)
end

--Update objects in the container when objects change
function TradeWindow.UpdateObject(window,updateId)
	if not WindowData.ObjectInfo[updateId] then
		RegisterWindowData(WindowData.ObjectInfo.Type, updateId)
	end
	local containerId = WindowData.ObjectInfo[updateId].containerId
	local containedItems
	local numItems
	local slotIndex
	local windowName
	
	-- if this object is in my container
	if( (TradeWindow.OpenContainers[window] == true) and ( TradeWindow.TradeInfo[window] ~= nil) ) then
		if( TradeWindow.TradeInfo[window].containerId == containerId ) then
			-- Create any contents slots we need for the container	
			windowName = window.."PlayerList"
		elseif (TradeWindow.TradeInfo[window].containerId2 == containerId) then
			windowName = window.."TraderList"
		end
	
		if( windowName ~= nil ) then
			-- find the slot index
			containedItems = WindowData.ContainerWindow[containerId].ContainedItems
			numItems = WindowData.ContainerWindow[containerId].numItems
			slotIndex = 0
			for i=1, numItems do
				if( containedItems[i].objectId == updateId ) then
					slotIndex = i
					break
				end
			end
			item = WindowData.ObjectInfo[updateId]

			local defaultName = windowName.."ScrollWindowScrollChildItem"..slotIndex

			-- Name
			local elementName = defaultName.."Name"
			if (wstring.lower(item.name) == GetStringFromTid(1041361)) then -- a bank check
				local prop = ItemProperties.GetObjectProperties( updateId, 4, "Trade window - bank check" )
				LabelSetText(elementName, item.name .. L"\n" .. prop)
			else	
				LabelSetText(elementName, item.name )
			end
			WindowSetShowing(elementName, true)
		
			-- Icon
			local elementIcon = defaultName.."Icon"
			if( item.iconName ~= "" ) then

                EquipmentData.UpdateItemIcon(elementIcon, item)	
				
				parent = WindowGetParent(elementIcon)
				WindowClearAnchors(elementIcon)
				WindowAddAnchor(elementIcon, "topleft", parent, "topleft", 15+((45-item.newWidth)/2), 15+((45-item.newHeight)/2))
				
				WindowSetShowing(elementIcon, true)
			else
				WindowSetShowing(elementIcon, false)
			end

		end
	end

        
end


function TradeWindow.DangerMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1155369))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.MyTradeTotalGoldMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156205))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.MyTradeTotalPlatMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156206))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.TheirTradeTotalGoldMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156207))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.TheirTradeTotalPlatMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156208))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.BalanceGoldMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156203))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end

function TradeWindow.BalancePlatMouseOver()
	Tooltips.CreateTextOnlyTooltip(SystemData.ActiveWindow.name,  GetStringFromTid(1156204))
	Tooltips.Finalize()
	Tooltips.AnchorTooltip( Tooltips.ANCHOR_WINDOW_TOP )
end


function TradeWindow.OnKeyDown()	
	local this = SystemData.ActiveWindow.name	
	local parentWindow = WindowGetParent(this)	
	local this = WindowGetParent(parentWindow)	
	
	local gold = tonumber(TextEditBoxGetText(this.."PlayerAcceptGoldAmountGold"))
	local plat = tonumber(TextEditBoxGetText(this.."PlayerAcceptGoldAmountPlat"))
	local goldBalance = tonumber(WindowData.TradeInfo.myGoldBalance)
	local platBalance = tonumber(WindowData.TradeInfo.myPlatBalance)

	local PLATINUM_SIZE = 1000000000
	if(gold >= PLATINUM_SIZE) then	
		gold = PLATINUM_SIZE-1
		TextEditBoxSetText(this.."PlayerAcceptGoldAmountGold", L""..gold)
	end

	if(plat >= PLATINUM_SIZE) then
		plat = PLATINUM_SIZE -1
		TextEditBoxSetText(this.."PlayerAcceptGoldAmountPlat", L""..plat)
	end
	
	if( (gold > goldBalance) and (plat >= platBalance ) )then
		gold = goldBalance
		TextEditBoxSetText(this.."PlayerAcceptGoldAmountGold", L""..gold)
	end

	if(plat > platBalance)then
		plat = platBalance
		TextEditBoxSetText(this.."PlayerAcceptGoldAmountPlat", L""..plat)
	end

	WindowData.TradeInfo.myTradeGold = gold
	WindowData.TradeInfo.myTradePlat = plat
	BroadcastEvent(SystemData.Events.TRADE_SEND_MODIFYGOLD_WINDOW)
end

function TradeWindow.OnKeyEnter()
	local this = SystemData.ActiveWindow.name
	WindowSetShowing(this, false)
	WindowSetShowing(this .. "WtihCommas", true)
end

function TradeWindow.OnKeyTab()
	local this = SystemData.ActiveWindow.name	
	local parentWindow = WindowGetParent(this)	
	local this = WindowGetParent(parentWindow)

	local playerAcceptGoldAmountPlat = this .. "PlayerAcceptGoldAmountPlat"
	local playerAcceptGoldAmountGold = this .. "PlayerAcceptGoldAmountGold"
	local platAmountWithCommas = playerAcceptGoldAmountPlat .. "WtihCommas"
	local goldAmountWithCommas = playerAcceptGoldAmountGold .. "WtihCommas"
	if WindowHasFocus(playerAcceptGoldAmountGold) then				
		WindowSetShowing(goldAmountWithCommas, true)	
		WindowSetShowing(playerAcceptGoldAmountGold, false)
		WindowSetShowing(platAmountWithCommas, false)
		WindowSetShowing(playerAcceptGoldAmountPlat, true)
		WindowAssignFocus(playerAcceptGoldAmountPlat, true)
	else
		WindowSetShowing(platAmountWithCommas, true)	
		WindowSetShowing(playerAcceptGoldAmountPlat, false)
		WindowSetShowing(goldAmountWithCommas, false)		
		WindowSetShowing(playerAcceptGoldAmountGold, true)
		WindowAssignFocus(playerAcceptGoldAmountGold, true)
	end
end

function TradeWindow.OnLButtonDown()
	local this = SystemData.ActiveWindow.name	
	local textBox = string.gsub(this, "WtihCommas", "")
	WindowSetShowing(this, false)
	WindowSetShowing(textBox, true)
	WindowAssignFocus(textBox, true)
end

function TradeWindow.OnTextChanged()
	local this = SystemData.ActiveWindow.name	
	local parentWindow = WindowGetParent(this)	
	local this = WindowGetParent(parentWindow)	
	local gold = tonumber(TextEditBoxGetText(this.."PlayerAcceptGoldAmountGold"))
	local plat = tonumber(TextEditBoxGetText(this.."PlayerAcceptGoldAmountPlat"))	
	local goldLabel = this .. "PlayerAcceptGoldAmountGoldWtihCommas"
	local platLabel = this .. "PlayerAcceptGoldAmountPlatWtihCommas"
	LabelSetText(goldLabel, WindowUtils.AddCommasToNumber(gold))
	LabelSetText(platLabel, WindowUtils.AddCommasToNumber(plat))
end
function TradeWindow.OnUpdate()	
	local this = SystemData.ActiveWindow.name
	local playerAcceptGoldAmountGold = this .. "PlayerAcceptGoldAmountGold"
	local playerAcceptGoldAmountPlat = this .. "PlayerAcceptGoldAmountPlat"	

	if not WindowHasFocus(playerAcceptGoldAmountGold) then		
		local goldAmountWithCommas = playerAcceptGoldAmountGold .. "WtihCommas"		
		WindowSetShowing(goldAmountWithCommas, true)		
		WindowSetShowing(playerAcceptGoldAmountGold, false)
	end
	
	if not WindowHasFocus(playerAcceptGoldAmountPlat) then		
		local platAmountWithCommas = playerAcceptGoldAmountPlat .. "WtihCommas" 		
		WindowSetShowing(platAmountWithCommas, true)		
		WindowSetShowing(playerAcceptGoldAmountPlat, false)
	end
end
