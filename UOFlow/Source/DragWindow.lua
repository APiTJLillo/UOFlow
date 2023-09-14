----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

DragWindow = {}

DragWindow.CurrentItem = {}
----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
 
----------------------------------------------------------------
-- DragWindow Functions
----------------------------------------------------------------
function DragWindow.Initialize()
    if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then
        WindowSetDimensions("DragWindow", SystemData.DragItem.itemWidth, SystemData.DragItem.itemHeight)
        WindowSetShowing("DragWindowAction",false)
        
        item = 
        {
			itemId = SystemData.DragItem.itemId,
            iconName = SystemData.DragItem.itemName,
            newWidth = SystemData.DragItem.itemWidth,
            newHeight = SystemData.DragItem.itemHeight,
            iconScale = SystemData.DragItem.itemScale,
            hueId = SystemData.DragItem.itemHueId,
            hue = SystemData.DragItem.itemHue,
			objectType = SystemData.DragItem.itemType,
			amount = SystemData.DragItem.DragAmount
        }
        DragWindow.CurrentItem = item
        EquipmentData.UpdateItemIcon("DragWindowItem", item)     

        DynamicImageSetTexture( "DragWindowIconMulti", "", 0, 0 ) 
        RegisterWindowData(WindowData.ObjectInfo.Type, item.itemId)
        local itemdata = WindowData.ObjectInfo[item.itemId]
		if not itemdata then
			RegisterWindowData(WindowData.ObjectInfo.Type, item.itemId)
			itemdata = WindowData.ObjectInfo[item.itemId]
		end

		if not item.amount and itemdata then
			item.amount = itemdata.quantity
		end

		if not item.amount or not itemdata then
			item.amount = 1
		end
		if itemdata and item.amount > 1 and item.objectType ~= 3821 and item.objectType ~= 3824 then
			EquipmentData.UpdateItemIcon("DragWindowIconMulti", item)  
		end
		if item.amount > 1 then
			LabelSetText("DragWindowQuantity", L"x" .. Knumber(item.amount))
		end
	elseif( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ACTION ) then
	    local x, y = WindowGetDimensions("DragWindowAction")
	    
	    local disabled = false
	    if( SystemData.DragItem.actionType == SystemData.UserAction.TYPE_MACRO_REFERENCE ) then
			disabled = not UserActionIsTargetModeCompat(SystemData.MacroSystem.STATIC_MACRO_ID, SystemData.DragItem.actionId, 0)
	    else
			disabled = not UserActionIsActionTypeTargetModeCompat(SystemData.DragItem.actionType)
		end
		
        WindowSetDimensions("DragWindow", x, y)
        HotbarSystem.UpdateActionButton("DragWindowAction", SystemData.DragItem.actionType, SystemData.DragItem.actionId, SystemData.DragItem.actionIconId, disabled )
	    WindowSetShowing("DragWindowItem",false)
	    
		local tintColor = HotbarSystem.TargetTypeTintColors[SystemData.Hotbar.TargetType.TARGETTYPE_NONE]
	    WindowSetTintColor("DragWindowActionOverlay",tintColor[1],tintColor[2],tintColor[3])
	    WindowSetShowing("DragWindowActionHotkeyBackground",false)   
    end
    
    DragWindow.Update()
end

function DragWindow.Shutdown()
	SystemData.DragItem.DragAmount = nil
end

function DragWindow.Update()
    local posX = SystemData.MousePosition.x/InterfaceCore.scale
    local posY = SystemData.MousePosition.y/InterfaceCore.scale

    WindowClearAnchors("DragWindow")
    if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then
		WindowAddAnchor("DragWindow", "topleft", "Root", "center", posX, posY)
    elseif( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ACTION ) then
        WindowAddAnchor("DragWindow", "topleft", "Root", "topleft", posX, posY)
    end
    
    if( SystemData.DragItem.DragType == SystemData.DragItem.TYPE_ITEM ) then
        WindowSetDimensions("DragWindow", SystemData.DragItem.itemWidth, SystemData.DragItem.itemHeight)
        WindowSetShowing("DragWindowAction",false)
        
        item = DragWindow.CurrentItem

        EquipmentData.UpdateItemIcon("DragWindowItem", item)     

        DynamicImageSetTexture( "DragWindowIconMulti", "", 0, 0 ) 
        
        RegisterWindowData(WindowData.ObjectInfo.Type, item.itemId)
        local itemdata = WindowData.ObjectInfo[item.itemId]
		if not itemdata then
			RegisterWindowData(WindowData.ObjectInfo.Type, item.itemId)
			itemdata = WindowData.ObjectInfo[item.itemId]
		end

		if not item.amount and itemdata then
			item.amount = itemdata.quantity
		end

		if not item.amount or not itemdata then
			item.amount = 1
		end
		if itemdata and item.amount > 1 and item.objectType ~= 3821 and item.objectType ~= 3824 then
			EquipmentData.UpdateItemIcon("DragWindowIconMulti", item)  
		end
		if item.amount > 1 then
			LabelSetText("DragWindowQuantity", L"x" .. Knumber(item.amount))
		end
	end
end
