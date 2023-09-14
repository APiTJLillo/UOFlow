----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

StaticTextWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
StaticTextWindow.FadeTimeId = {}
StaticTextWindow.TimePassed = {}
StaticTextWindow.AlphaStart = 1
StaticTextWindow.AlphaDiff = 0.5
StaticTextWindow.FadeStartTime = 4
StaticTextWindow.numWindow = 0

StaticTextWindow.Gray   = { r=200, g=200, b=200 } --- GREY/SYS

----------------------------------------------------------------
-- StaticTextWindow Functions
----------------------------------------------------------------

function StaticTextWindow.Initialize()
	StaticTextWindow.numWindow = 0
	WindowRegisterEventHandler("Root", SystemData.Events.STATIC_TEXT_CREATE, "StaticTextWindow.CreateWindow")
	WindowRegisterEventHandler("Root", SystemData.Events.STATIC_TEXT_DESTROY_ALL, "StaticTextWindow.DestroyAllWindows")
end

function StaticTextWindow.CreateWindow()
	StaticTextWindow.DestroyAllWindows()

	StaticTextWindow.numWindow = StaticTextWindow.numWindow + 1

	local staticId = StaticTextWindow.numWindow	

	local windowName = "StaticTextWindow_"..staticId
	CreateWindowFromTemplate(windowName, "StaticTextWindow", "Root")
	
	WindowSetId(windowName, staticId)
	StaticTextWindow.FadeTimeId[staticId] = StaticTextWindow.AlphaStart
	StaticTextWindow.TimePassed[staticId] = 0
	local offset = 0
	if (WindowData.StaticTextWindow.ObjectType < 16384) then
		offset = 1020000
	elseif (WindowData.StaticTextWindow.ObjectType < 32768) then
		offset = 1095256 - 16384
	elseif (WindowData.StaticTextWindow.ObjectType < 65536) then
		offset = 1116792 - 32768
	end
	local tid = WindowData.StaticTextWindow.ObjectType + offset
	local name = GetStringFromTid(tid)
	local labelName = windowName.."Text"

	if( name == nil ) then
	    name = L""
	end
	if (SystemData.Settings.Language.type ~= SystemData.Settings.Language.LANGUAGE_ENU) then
		LabelSetFont(labelName, "UO_DefaultText", WindowUtils.FONT_DEFAULT_TEXT_LINESPACING)
	end
	LabelSetText(labelName, name)

	local hue = StaticTextWindow.Gray
	LabelSetTextColor(labelName, hue.r, hue.g, hue.b)

	local xPosition = WindowData.StaticTextWindow.XPos
	local yPosition = WindowData.StaticTextWindow.YPos

	StaticTextWindow.HandleAnchorWindow(windowName, xPosition, yPosition)

end

function StaticTextWindow.DestroyAllWindows()
	for i, id in pairs(StaticTextWindow.FadeTimeId) do
		local windowName = "StaticTextWindow_"..i
		DestroyWindow(windowName)
		StaticTextWindow.FadeTimeId[i] = nil
		StaticTextWindow.TimePassed[i] = nil
	end
end

function StaticTextWindow.HandleAnchorWindow(windowName, xPosition, yPosition)
	local propWindowWidth = 200
	local propWindowHeight = 30
	local propWindowX 
	local propWindowY
	-- Set the position
	local scaleFactor = 1/InterfaceCore.scale	
	
	local mouseX = xPosition - 100
	if ( mouseX + (propWindowWidth / scaleFactor) > SystemData.screenResolution.x ) then
		propWindowX = mouseX - (propWindowWidth / scaleFactor)
	else
		propWindowX = mouseX
	end
		
	local mouseY = yPosition - 15
	if ( mouseY + (propWindowHeight / scaleFactor) > SystemData.screenResolution.y ) then
		propWindowY = mouseY - (propWindowHeight / scaleFactor)
	else
		propWindowY = mouseY
	end

	--Debug.Print("Window offset xPos = "..propWindowX.."y = "..propWindowY)
	WindowClearAnchors(windowName)
	WindowAddAnchor(windowName,"topleft","Root" , "topleft", propWindowX * scaleFactor, propWindowY * scaleFactor)
end

function StaticTextWindow.Shutdown()
	local this = SystemData.ActiveWindow.name
	local staticId = WindowGetId(this)
end

function StaticTextWindow.Update( timePassed )
	for i, id in pairs(StaticTextWindow.FadeTimeId) do
		StaticTextWindow.TimePassed[i] = StaticTextWindow.TimePassed[i] + timePassed
		if(StaticTextWindow.TimePassed[i] > StaticTextWindow.FadeStartTime ) then
			local windowName = "StaticTextWindow_"..i
			StaticTextWindow.FadeTimeId[i] = StaticTextWindow.FadeTimeId[i] - StaticTextWindow.AlphaDiff
			if(StaticTextWindow.FadeTimeId[i] <= 0) then
				--Remove Name Window
				StaticTextWindow.FadeTimeId[i] = nil
				StaticTextWindow.TimePassed[i] = nil
				DestroyWindow(windowName)
			else
				local labelName = windowName.."Text"
				WindowSetFontAlpha( labelName, StaticTextWindow.FadeTimeId[i])
			end
		end
	end
end