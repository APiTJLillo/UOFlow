----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

Compass = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

Compass.WindowName = "Compass"
Compass.Needle = Compass.WindowName .. "Needle"
Compass.Label = Compass.WindowName .. "Label"
Compass.MagnetPoint = {waypointId = nil; x = 0; y = 0; facet = 0;}
Compass.delta = 0

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function Compass.Initialize()
    WindowUtils.RestoreWindowPosition(Compass.WindowName)
    SnapUtils.SnappableWindows["Compass"] = true
	WindowSetShowing(Compass.WindowName, false)
end

function Compass.Shutdown()
    WindowUtils.SaveWindowPosition(Compass.WindowName)
    SnapUtils.SnappableWindows["Compass"] = nil
end

function Compass.Close()		
	WindowSetShowing(Compass.WindowName, false)
end

function Compass.Magnetize(timepassed)
	Compass.delta = Compass.delta + timepassed
	if Compass.delta > math.random(0,1) then
		Compass.delta = 0
		local wx = tonumber(Compass.MagnetPoint.x)
		local wy = tonumber(Compass.MagnetPoint.y)
		local wfacet = tonumber(Compass.MagnetPoint.facet)
		if Compass.MagnetPoint.waypointId then
			local windowName = "Waypoint"..Compass.MagnetPoint.waypointId..MapCommon.ActiveView
			if (waypointId < 10000 ) then
				wtype, wflags, wname, wfacet, wx, wy, wz = UOGetWaypointInfo(Compass.MagnetPoint.waypointId)
			end
		end
		
		local deltaX = WindowData.PlayerLocation.x - wx
		local deltaY = WindowData.PlayerLocation.y - wy
		
		local distance = math.ceil(math.sqrt(math.pow(deltaX, 2) + math.pow(deltaY, 2)))
		
		local angle = math.ceil(8 * (1 + math.deg(math.atan2( deltaX, deltaY )) / 360) - 0.5) % 8
		angle = (angle * -45) + 45
		local shaking = 1
	
		if distance <= 0 or WindowData.PlayerLocation.facet ~= wfacet then
			shaking = 360
		elseif distance < 10 then
			shaking = 5
		elseif distance < 20 then
			shaking = 4
		elseif distance < 30 then
			shaking = 3
		elseif distance < 50 then
			shaking = 2
		end
		angle = angle + math.ceil(math.random(-shaking,shaking))
		DynamicImageSetRotation(Compass.Needle, angle)
		
		if WindowData.PlayerLocation.facet ~= wfacet then
			local facets = {
				GetStringFromTid(1012001), --fel
				GetStringFromTid(1012000), -- tramm
				GetStringFromTid(1012002), -- ilsh
				GetStringFromTid(1060643), -- malas
				GetStringFromTid(1063258), -- tok
				GetStringFromTid(1112178), -- ter
				}
			if (facets[wfacet+1]) then
				
				
				local moongates = {}
				for map, array in pairs(Waypoints.Facet) do
					if map == WindowData.PlayerLocation.facet then
						for i = 1, #array do
							local arr = array[i]
							if string.find(string.lower(array[i].Name), "moongate") then
								arr.deltaX = WindowData.PlayerLocation.x - array[i].x
								arr.deltaY = WindowData.PlayerLocation.y - array[i].y

								arr.Distance = math.ceil(math.sqrt(math.pow(arr.deltaX, 2) + math.pow(arr.deltaY, 2)))
								table.insert(moongates, arr)
							end
						end
					end
				end
				local bestDist = nil
				for i = 1, #moongates do
					if not bestDist then
						bestDist = moongates[i]
					else
						if bestDist.Distance > moongates[i].Distance then
							bestDist = moongates[i]
						end
					end
				end
				
				local distance = bestDist.Distance
				
				local angle = math.ceil(8 * (1 + math.deg(math.atan2( bestDist.deltaX, bestDist.deltaY )) / 360) - 0.5) % 8
				angle = (angle * -45) + 45
				local shaking = 1
			
				if distance <= 0 then
					shaking = 360
				elseif distance < 10 then
					shaking = 5
				elseif distance < 20 then
					shaking = 4
				elseif distance < 30 then
					shaking = 3
				elseif distance < 50 then
					shaking = 2
				end
				angle = angle + math.ceil(math.random(-shaking,shaking))
				DynamicImageSetRotation(Compass.Needle, angle)
				
				LabelSetText(Compass.Label, ReplaceTokens(GetStringFromTid(1154862), {facets[wfacet+1],towstring(distance)}))
				
			else
				LabelSetText(Compass.Label, GetStringFromTid(1154861))
			end
		else
			LabelSetText(Compass.Label, ReplaceTokens(GetStringFromTid(1154863), {towstring(distance)}))
		end
	end
end