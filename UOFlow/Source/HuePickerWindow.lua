----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

HuePickerWindow = {}

HuePickerWindow.NUM_COLORS = 200
HuePickerWindow.COLORS_PER_ROW = 20
HuePickerWindow.SWATCH_SIZE = 15

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

----------------------------------------------------------------
-- MainMenuWindow Functions
----------------------------------------------------------------

-- OnInitialize Handler
function HuePickerWindow.Initialize()
    ButtonSetText("PickColorTarget", L"Pick!")
	LabelSetText("Color2Label", L"(Text) WHITE              " )
    LabelSetText("Color2Label", L"(Plant) Bright Green" )
    LabelSetText("Color3Label", L"(Plant) Bright Yellow" )
    LabelSetText("Color4Label", L"(Plant) Bright Purple" )
    LabelSetText("Color5Label", L"(Plant) Purple" )
    LabelSetText("Color6Label", L"(Plant) Rare Pink" )
    LabelSetText("Color7Label", L"(Plant) Rare Aqua" )
    LabelSetText("Color8Label", L"(Pigments) Fresh Plum" )
    LabelSetText("Color10Label", L"(Pigments) Light Green" )
    LabelSetText("Color11Label", L"(Pigments) Pale Blue" )
    LabelSetText("Color12Label", L"(Pigments) Noble Gold" )
    LabelSetText("Color13Label", L"(Pigments) Pale Orange" )
    LabelSetText("Color14Label", L"(Pigments) Chaos Blue" )
    LabelSetText("Color15Label", L"(Pigments) Berserker Red" )
    LabelSetText("Color16Label", L"(Special) Sigil Purple" )
    LabelSetText("Color17Label", L"(Special) Museum Chaos Shield" )
    LabelSetText("Color18Label", L"(Special) Crimson Red" )

    local id = WindowData.HuePicker.ObjectId
	
    local windowName = SystemData.ActiveWindow.name


    Interface.DestroyWindowOnClose[windowName] = true
	
	HuePickerWindow[id] = {}
	if (text == nil) then
		HuePickerWindow[id].ListType = WindowData.HuePicker.ListType
	else
		HuePickerWindow[id].ListType = 0
	end
	HuePickerWindow[id].Brightness = 0

    
    WindowSetId(windowName,id)
    WindowSetId(windowName.."SliderBar", id)
	
        ColorPickerWindow.SetNumColorsPerRow(HuePickerWindow.COLORS_PER_ROW)
    	ColorPickerWindow.SetSwatchSize(HuePickerWindow.SWATCH_SIZE)
    	ColorPickerWindow.SetAfterColorSelectionFunction(HuePickerWindow.ColorPicked)
    	ColorPickerWindow.SetWindowPadding(1,1)
    	ColorPickerWindow.SetFrameEnabled(false)
    	ColorPickerWindow.SetCloseButtonEnabled(false)
    	WindowSetShowing(windowName.."Chrome_UO_WindowCloseButton", false)
   	LabelSetText(windowName.."Name", GetStringFromTid( 3000166 ) )
    
   	HuePickerWindow.UpdateHueTable(windowName.."Picker",id,1)
   	WindowSetScale(windowName, 0.60)
    WindowSetScale(windowName.."Picker", 0.60)
end

function HuePickerWindow.Shutdown()

end

function HuePickerWindow.OnSlide()
	local sliderName =SystemData.ActiveWindow.name
	local id = WindowGetId(sliderName)
	
	local windowName = "HuePicker"..id
	if (id == 0) then
		windowName = "HuePickerWindow"
	end
	
	local sliderValue = ( SliderBarGetCurrentPosition( sliderName ) / 0.25 ) + 1

	if ( HuePickerWindow[id].Brightness ~= sliderValue ) then
		HuePickerWindow.UpdateHueTable(windowName.."Picker", id, sliderValue)
	end
end

function HuePickerWindow.UpdateHueTable(this,id,newBrightness)

local hueTable = {}

    if( newBrightness ~= HuePickerWindow[id].Brightness ) then
        HuePickerWindow[id].Brightness = newBrightness
    
        for i=1, HuePickerWindow.NUM_COLORS do
            hueTable[i] = ((i-1)*5)+HuePickerWindow[id].Brightness + 1
        end
    end
    
    ColorPickerWindow.SetColorTable(hueTable,this)
    ColorPickerWindow.DrawColorTable(this)	    

end
function HuePickerWindow.PickColorTarget()
	local this = SystemData.ActiveWindow.name
	HuePickerWindow.RequestTargetInfo(this)	
end


function HuePickerWindow.Color2Up()
	local this = SystemData.ActiveWindow.name
    	local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	if (id == 0) then
		HuePickerWindow.PickColor(id, 0,huePickerWindow)
	else
		HuePickerWindow.PickColor(id, 671,huePickerWindow)
	end
	
end

function HuePickerWindow.Color3Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 253,huePickerWindow)
end

function HuePickerWindow.Color4Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 316,huePickerWindow)
end

function HuePickerWindow.Color5Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 15,huePickerWindow)
end

function HuePickerWindow.Color6Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 341,huePickerWindow)
end

function HuePickerWindow.Color7Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 391,huePickerWindow)
end

function HuePickerWindow.Color8Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 325,huePickerWindow)
end


function HuePickerWindow.Color10Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 456,huePickerWindow)
end

function HuePickerWindow.Color11Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 591,huePickerWindow)
end

function HuePickerWindow.Color12Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 551,huePickerWindow)
end

function HuePickerWindow.Color13Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 46,huePickerWindow)
end

function HuePickerWindow.Color14Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 5,huePickerWindow)
end

function HuePickerWindow.Color15Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 33,huePickerWindow)
end

function HuePickerWindow.Color16Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 11,huePickerWindow)
end

function HuePickerWindow.Color17Up()
	local this = SystemData.ActiveWindow.name
    	local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 250,huePickerWindow)
end

function HuePickerWindow.Color18Up()
	local this = SystemData.ActiveWindow.name
    local huePickerWindow = WindowGetParent(this)
	local id = WindowGetId(huePickerWindow)
	HuePickerWindow.PickColor(id, 232, huePickerWindow)
end

function HuePickerWindow.PickColor(id, huePicked, this)
	--Debug.Print(huePicked)
	HuePickerColorSelected(id,HuePickerWindow[id].ListType,huePicked)
	
	DestroyWindow(this)
end


function HuePickerWindow.RequestTargetInfo()
	local windowName = SystemData.ActiveWindow.name
	RequestTargetInfo()
	WindowRegisterEventHandler(windowName, SystemData.Events.TARGET_SEND_ID_CLIENT, "HuePickerWindow.RequestTargetInfoReceived")
end

function HuePickerWindow.RequestTargetInfoReceived()
	local windowName = SystemData.ActiveWindow.name
	local objectId = SystemData.RequestInfo.ObjectId
	WindowUnregisterEventHandler(windowName, SystemData.Events.TARGET_SEND_ID_CLIENT)

	local this = SystemData.ActiveWindow.name
    	local huePickerWindow = WindowGetParent(this)
    if( objectId ~= 0) then 
		if not WindowData.ObjectInfo[objectId] then
			RegisterWindowData(WindowData.ObjectInfo.Type,WindowData.CurrentTarget.TargetId)
		end
		local item = WindowData.ObjectInfo[objectId]
		if (item ~= nil) then			
			--Debug.Print("Hue: "..item.hueId)			
			--Debug.Print("Hue.r: "..item.hue.r)
			--Debug.Print("Hue.g: "..item.hue.g)
			--Debug.Print("Hue.b: "..item.hue.b)
			local id = WindowGetId(huePickerWindow)
			if item.hueId > 999 or item.hueId == 0 then
				WindowUtils.SendOverheadText(GetStringFromTid(503281), 33, true) -- Error: This is not a valid hue
			else
				HuePickerWindow.PickColor(id, item.hueId, huePickerWindow)
			end
		else
			WindowUtils.SendOverheadText(GetStringFromTid(503281), 33, true) -- Error: This is not a valid hue		
		end
    end
end

function HuePickerWindow.ColorPicked(windowName)
    local huePicked = ColorPickerWindow.colorSelected[windowName]    	
    local huePickerWindow = WindowGetParent(windowName)
    local id = WindowGetId(huePickerWindow)
	WindowSetShowing(windowName, true)
	HuePickerWindow.PickColor(id,huePicked, huePickerWindow)
end