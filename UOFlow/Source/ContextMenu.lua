----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ContextMenu = {}

ContextMenu.GREYEDOUT 	= 0x01
ContextMenu.SECONDTIER 	= 0x02
ContextMenu.HIGHLIGHTED	= 0x04

ContextMenu.HighlightColor = { r=51, g=102, b=255 }
ContextMenu.DisabledColor = { r=128, g=128, b=128 }
ContextMenu.NormalColor = { r=255, g=255, b=255}

ContextMenu.WINDOW_WIDTH = 275
ContextMenu.ITEM_WINDOW_WIDTH = 270
ContextMenu.ITEM_WINDOW_HEIGHT = 25
ContextMenu.ITEM_WINDOW_SPACING = 2

ContextMenu.NumItemsCreated = {}

-- These variables are used when the context menu is lua drive
ContextMenu.IsLuaDriven = false
ContextMenu.LuaMenuOptions = {}
ContextMenu.LuaCallback = nil

ContextMenu.SubMenuDelayTimer = nil

ContextMenu.DefaultValues = {}
ContextMenu.DefaultValues.VendorBuy = 110
ContextMenu.DefaultValues.VendorSell = 111
ContextMenu.DefaultValues.OpenBankbox = 120
ContextMenu.DefaultValues.PetGuard = 130
ContextMenu.DefaultValues.PetFollow = 131
ContextMenu.DefaultValues.PetKill = 134
ContextMenu.DefaultValues.PetStay = 135
ContextMenu.DefaultValues.PetStop = 137
ContextMenu.DefaultValues.Tame = 301
ContextMenu.DefaultValues.NPCTalk = 303
ContextMenu.DefaultValues.CancelProtection = 308
ContextMenu.DefaultValues.EnablePVPWarning = 320
ContextMenu.DefaultValues.BodRequest = 403
ContextMenu.DefaultValues.ViewQuestLog = 404
ContextMenu.DefaultValues.CancelQuest = 405
ContextMenu.DefaultValues.QuestConversation = 406
ContextMenu.DefaultValues.InsuranceMenu = 416
ContextMenu.DefaultValues.ToggleItemInsurance = 418
ContextMenu.DefaultValues.Bribe = 419
ContextMenu.DefaultValues.OpenPaperdoll = 520
ContextMenu.DefaultValues.ReleaseCoOwnership = 602
ContextMenu.DefaultValues.LeaveHouse = 604
ContextMenu.DefaultValues.UnpackTransferCrate = 622
ContextMenu.DefaultValues.LoadShuriken = 701
ContextMenu.DefaultValues.QuestItem = 801
ContextMenu.DefaultValues.AddPartyMember = 810
ContextMenu.DefaultValues.RemovePartyMember = 811
ContextMenu.DefaultValues.SiegeBless = 820
ContextMenu.DefaultValues.LoyaltyRating = 915
ContextMenu.DefaultValues.TitlesMenu = 918
ContextMenu.DefaultValues.VoidPool = 1010
ContextMenu.DefaultValues.AllowTrades = 1013
ContextMenu.DefaultValues.RefuseTrades = 1014

----------------------------------------------------------------
-- ContextMenu Functions
----------------------------------------------------------------

-- subMenuOptions is a table that contains the same information as the main item
-- tid, flags, returnCode, param, pressed
function ContextMenu.CreateLuaContextMenuItem(tid,flags,returnCode,param,pressed,subMenuOptions, subMenuDelay, textColor)
	local index = table.getn(ContextMenu.LuaMenuOptions) + 1

	ContextMenu.LuaMenuOptions[index] = { tid=tid, flags=flags, returnCode=returnCode, param=param, pressed=pressed, subMenuOptions=subMenuOptions, subMenuDelay=subMenuDelay, textColor=textColor}
end

function ContextMenu.CreateLuaContextMenuItemWithString(str,flags,returnCode,param,pressed,subMenuOptions,subMenuDelay,textColor)
	local index = table.getn(ContextMenu.LuaMenuOptions) + 1

	ContextMenu.LuaMenuOptions[index] = { str=str, flags=flags, returnCode=returnCode, param=param, pressed=pressed, subMenuOptions=subMenuOptions, subMenuDelay=subMenuDelay, textColor=textColor}
end

function ContextMenu.ActivateLuaContextMenu(callback)
	ContextMenu.LuaCallback = callback
	ContextMenu.IsLuaDriven = true
	if WindowData.ContextMenu then
		WindowData.ContextMenu.hideMenu = 0
	end
	WindowSetShowing("ContextMenu",true)
end

function ContextMenu.GetMenuItemData()
	if( ContextMenu.IsLuaDriven == true ) then
		return ContextMenu.LuaMenuOptions
	elseif( WindowData.ContextMenu ~= nil ) then
		return WindowData.ContextMenu.menuItems
	end
end

function ContextMenu.ExecuteMenuItem(returnCode,param)
	if( ContextMenu.IsLuaDriven == true ) then
		ContextMenu.IsLuaDriven = false
		--WindowSetShowing("ContextMenu",false)
		ContextMenu.LuaCallback(returnCode,param)
	else
		--Debug.Print(returnCode)
		if WindowData.ContextMenu and WindowData.ContextMenu.hideMenu == 1 then
			WindowSetShowing("ContextMenu", false)
		end
		if returnCode == 919 then
			Interface.RenamePet(WindowData.ContextMenu.objectId)
		else
			WindowData.ContextMenu.returnCode = returnCode
			BroadcastEvent(SystemData.Events.CONTEXT_MENU_SELECTED) 
		end
	end
end

-- OnInitialize Handler
function ContextMenu.Initialize()
	WindowSetAlpha("ContextMenuWindowBackground", 0.8)
	
	CreateWindow("ContextMenuSubMenu", false)
end

-- OnShown handler
function ContextMenu.Show()
	if WindowData.ContextMenu and WindowData.ContextMenu.hideMenu == 1 then
		WindowSetShowing("ContextMenu", false)
		return
	end
	this = WindowUtils.GetActiveDialog()
	local menuItems = ContextMenu.GetMenuItemData()
	
	-- Create any extra menu items that might be needed
	local len = table.getn(menuItems)
	
	ContextMenu.CreateMenuItems(len,"ContextMenu")
	local cmWidth, cmHeight = ContextMenu.FillMenuItems(menuItems,"ContextMenu")	
	--Debug.Print("len: " ..len)
	
	-- Set the position
	scaleFactor = 1/InterfaceCore.scale	
	
	mouseX = SystemData.MousePosition.x
	if mouseX + (cmWidth / scaleFactor) > SystemData.screenResolution.x then
		cmWindowX = mouseX - (cmWidth / scaleFactor)
	else
		cmWindowX = mouseX
	end
		
	mouseY = SystemData.MousePosition.y
	cmWindowY = mouseY
	if mouseY + (cmHeight / scaleFactor) > SystemData.screenResolution.y then
		cmWindowY = mouseY - (cmHeight / scaleFactor)
	else
		cmWindowY = mouseY
	end

	WindowSetOffsetFromParent("ContextMenu", cmWindowX * scaleFactor, cmWindowY * scaleFactor)	
end

function ContextMenu.Hide()
    if( WindowData.ContextMenu ~= nil ) then
	    WindowData.ContextMenu.menuItems = {}
	end
	ContextMenu.LuaMenuOptions = {}
	ContextMenu.IsLuaDriven = false
	-- reset submenu timer
	ContextMenu.SubMenuDelayTimer = nil
	if WindowData.ContextMenu then
		WindowData.ContextMenu.menuItems = nil
	end
end

function ContextMenu.CreateMenuItems(numItemsNeeded,menuWindow)
	ContextMenu.HideAllItems(menuWindow)

	local numHave
	
	if( ContextMenu.NumItemsCreated[menuWindow] == nil ) then
		numHave = 0
	else
		numHave = ContextMenu.NumItemsCreated[menuWindow]
	end
	
	if numHave >= numItemsNeeded then
		return
	end

	for i = numHave + 1, numItemsNeeded do
		itemName = menuWindow.."Item"..i
		
		CreateWindowFromTemplate(itemName, "ContextMenuEntryDef", menuWindow)

		if i == 1 then
			WindowAddAnchor(itemName, "topleft", menuWindow, "topleft", 3, ContextMenu.ITEM_WINDOW_SPACING)
		else
			WindowAddAnchor(itemName, "bottomleft", menuWindow.."Item"..i-1, "topleft", 0, ContextMenu.ITEM_WINDOW_SPACING)
		end
	end
	
	ContextMenu.NumItemsCreated[menuWindow] = numItemsNeeded
end

function ContextMenu.FillMenuItems(menuItems,menuWindow,submenuIndex)
	local len = table.getn(menuItems) 
	
	for i = 1, len do
		--Debug.Print("Adding item index "..i.." menuWindow "..menuWindow)
	
		itemName = menuWindow.."Item"..i
		item = menuItems[i]
		--Debug.Print(L"ITEMTEXT: " .. GetStringFromTid(item.tid))
		if (item.tid) then
			ButtonSetText(itemName, GetStringFromTid(item.tid))
		else
			ButtonSetText(itemName, item.str)
		end
		
		if item.textColor then
			hueR,hueG,hueB,hueA = HueRGBAValue(item.textColor)
			ButtonSetTextColor(itemName, Button.ButtonState.NORMAL, hueR, hueG, hueB)
		elseif item.flags & ContextMenu.GREYEDOUT == 0 then
			ButtonSetTextColor(itemName, Button.ButtonState.NORMAL, ContextMenu.NormalColor.r, ContextMenu.NormalColor.g, ContextMenu.NormalColor.b)
		end
		
		if( item.pressed == true ) then
			ButtonSetPressedFlag(itemName, true)
		else
			ButtonSetPressedFlag(itemName, false)
		end
		
		if( submenuIndex ~= nil and submenuIndex > 0 ) then
			local offset = submenuIndex * 100
			WindowSetId(itemName, i+offset)
		else
			WindowSetId(itemName, i)
		end
		
		WindowSetShowing(itemName, true)
		if item.flags & ContextMenu.GREYEDOUT ~= 0 then
			ButtonSetDisabledFlag(itemName, true)
			ButtonSetPressedFlag(itemName, false)
		else
			-- In case we previously set this item to disabled for a different menu
			ButtonSetDisabledFlag(itemName, false)
		end
		
		if item.flags & ContextMenu.HIGHLIGHTED ~= 0 then
			col = ContextMenu.HighlightColor
			ButtonSetTextColor(itemName, Button.ButtonState.NORMAL, col.r, col.g, col.b)
		end
		
	end
	
	
	local cmWidth = ContextMenu.WINDOW_WIDTH
	local cmHeight = len*(ContextMenu.ITEM_WINDOW_HEIGHT+ContextMenu.ITEM_WINDOW_SPACING)+5
	WindowSetDimensions(menuWindow, cmWidth, cmHeight)
	--Debug.Print("CM Height = "..cmHeight)
	
	return cmWidth, cmHeight
end

function ContextMenu.HideAllItems(menuWindow)
	numHave = ContextMenu.NumItemsCreated[menuWindow]
	
	if numHave then
		for i = 1, numHave do
			WindowSetShowing(menuWindow.."Item"..i, false)
		end
	end
	-- reset submenu timer
	ContextMenu.SubMenuDelayTimer = nil
end

function ContextMenu.MenuItemLButtonUp()
	this = SystemData.ActiveWindow.name
	local id = WindowGetId(this)
	local dialog = WindowUtils.GetActiveDialog()
	local itemData = ContextMenu.GetMenuItemData()
	
	if( id < 100 ) then
		menuOption = itemData[id]
	else
		local parentId = math.floor(id / 100)
		local subMenuId = id - (parentId*100)
		--Debug.Print("ParentId="..parentId.." subMenuId="..subMenuId)
		menuOption = itemData[parentId].subMenuOptions[subMenuId]
	end
	
	if menuOption and menuOption.returnCode then
		-- If menu option is disabled, DON'T click it!
		if menuOption.flags & ContextMenu.GREYEDOUT ~= 0 then
			return
		end
		
		ContextMenu.ExecuteMenuItem(menuOption.returnCode,menuOption.param)
	else
		--Debug.Print("Error showing context menu: either menuOption or menuOption.returnCode was nil.")
	end
	
	if menuOption and menuOption.textColor then
		hueR,hueG,hueB,hueA = HueRGBAValue(menuOption.textColor)
		ButtonSetTextColor(this, Button.ButtonState.NORMAL, hueR, hueG, hueB)
	end

	WindowSetShowing("ContextMenu", false)	
	WindowSetShowing("ContextMenuSubMenu", false)	
end

function ContextMenu.MenuItemLButtonDown()
	--Debug.Print("LButtonDown")
	
	this = SystemData.ActiveWindow.name
	local id = WindowGetId(this)
	local itemData = ContextMenu.GetMenuItemData()
	if( id < 100 ) then
		menuOption = itemData[id]
	else
		local parentId = math.floor(id / 100)
		local subMenuId = id - parentId*100
		menuOption = itemData[parentId].subMenuOptions[subMenuId]
	end
	
	if menuOption and (menuOption.flags & ContextMenu.GREYEDOUT ~= 0) then
		col = ContextMenu.DisabledColor
		ButtonSetTextColor(this, Button.ButtonState.NORMAL, col.r, col.g, col.b)
	end

	if menuOption and menuOption.textColor then
		hueR,hueG,hueB,hueA = HueRGBAValue(menuOption.textColor)
		ButtonSetTextColor(this, Button.ButtonState.NORMAL, hueR, hueG, hueB)
	end
end

function ContextMenu.Update(timePassed)
	if not WindowGetShowing("ContextMenu") then
		return
	end
	if ContextMenu.SubMenuDelayTimer == nil then
		--no sub menu timer
		return
	end

	ContextMenu.SubMenuDelayTimer = ContextMenu.SubMenuDelayTimer - timePassed
	if ContextMenu.SubMenuDelayTimer > 0 then
		--still have to waite
		return
	end

	--time to show the sub menu
	
	--reset timer
	ContextMenu.SubMenuDelayTimer = nil
	
	--show sub menu
	local menuItems = ContextMenu.GetMenuItemData()
	local len = table.getn(menuItems[ContextMenu.SubMenuParentId].subMenuOptions)
	ContextMenu.CreateMenuItems(len,"ContextMenuSubMenu")
	ContextMenu.FillMenuItems(menuItems[ContextMenu.SubMenuParentId].subMenuOptions,"ContextMenuSubMenu",ContextMenu.SubMenuParentId)
	WindowSetShowing("ContextMenuSubMenu",true)
	WindowClearAnchors("ContextMenuSubMenu")

	-- anchor the sub window based on the main window position
	local width, height = WindowGetDimensions("ContextMenuSubMenu")
	local anchorPosX, anchorPosY = WindowGetScreenPosition(ContextMenu.SubMenuParentItemName)
	if( anchorPosY + height > SystemData.screenResolution.y ) then
		WindowAddAnchor("ContextMenuSubMenu","bottomright",ContextMenu.SubMenuParentItemName,"bottomleft",0,0)
	else
		WindowAddAnchor("ContextMenuSubMenu","topright",ContextMenu.SubMenuParentItemName,"topleft",0,0)
	end
end

function ContextMenu.MenuItemMouseOver()
	this = SystemData.ActiveWindow.name
	local id = WindowGetId(this)
	local menuItems = ContextMenu.GetMenuItemData()
	
	if( id < 100 ) then
		if( menuItems[id] and menuItems[id].subMenuOptions ~= nil ) then
			-- set sub menu timer
			if menuItems[id].subMenuDelay == nil then
				ContextMenu.SubMenuDelayTimer = 0
			else
				ContextMenu.SubMenuDelayTimer = menuItems[id].subMenuDelay
			end

			ContextMenu.SubMenuParentId = id
			ContextMenu.SubMenuParentItemName = this
		end

		WindowSetShowing("ContextMenuSubMenu",false)
	end

	local menuOption = menuItems[id]
	if id > 100 then
		local parentId = math.floor(id / 100)
		local subMenuId = id - parentId*100
		menuOption = menuItems[parentId].subMenuOptions[subMenuId]
	end
	if menuOption and menuOption.textColor then
		hueR,hueG,hueB,hueA = HueRGBAValue(menuOption.textColor)
		ButtonSetTextColor(this, Button.ButtonState.NORMAL, hueR, hueG, hueB)
	end
end

function ContextMenu.MenuItemMouseLeave()
	this = SystemData.ActiveWindow.name
	local id = WindowGetId(this)
	local menuItems = ContextMenu.GetMenuItemData()

	-- reset submenu timer
	ContextMenu.SubMenuDelayTimer = nil
	
	if( menuItems ~= nil ) then
		local menuOption = menuItems[id]
		if id > 100 then
			local parentId = math.floor(id / 100)
			local subMenuId = id - parentId*100
			if menuItems[parentId] and menuItems[parentId].subMenuOptions then
				menuOption = menuItems[parentId].subMenuOptions[subMenuId]
			end
		end
		
		if menuOption and (menuOption.flags & ContextMenu.HIGHLIGHTED ~= 0) then
			col = ContextMenu.HighlightColor
			ButtonSetTextColor(this, Button.ButtonState.NORMAL, col.r, col.g, col.b)
		end
		
		if menuOption and menuOption.textColor then
			hueR,hueG,hueB,hueA = HueRGBAValue(menuOption.textColor)
			ButtonSetTextColor(this, Button.ButtonState.NORMAL, hueR, hueG, hueB)
		end
	end
end

function ContextMenu.RequestContextAction(ownerId, actionId)
	WindowData.ContextMenu.hideMenu = 1
	RequestContextMenu(ownerId, false)

	WindowData.ContextMenu.returnCode = actionId
	BroadcastEvent(SystemData.Events.CONTEXT_MENU_SELECTED)
end