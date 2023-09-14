----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CourseMapWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

CourseMapWindow.X_PADDING = 16
CourseMapWindow.Y_PADDING = 76

CourseMapWindow.X_MAPPOINT_PADDING = 10
CourseMapWindow.Y_MAPPOINT_PADDING = 10

CourseMapWindow.NumPointsCreated = {}
CourseMapWindow.MapPoints = {}

CourseMapWindow.DragMapPoint = ""

CourseMapWindow.WINDOWSCALE = 1.4

CourseMapWindow.TID = {
	PlotCourse = 3000180,
	StopPlotting = 3000181,
	ClearCourse = 3000182
}

CourseMapWindow.TreasureMaps = {
	[1041510] = true; -- a tattered, youthful treasure map
	[1041511] = true; -- a tattered, plainly drawn treasure map
	[1041512] = true; -- a tattered, expertly drawn treasure map
	[1041513] = true; -- a tattered, adeptly drawn treasure map
	[1041514] = true; -- a tattered, cleverly drawn treasure map
	[1041515] = true; -- a tattered, deviously drawn treasure map
	[1063452] = true; -- a tattered, ingeniously drawn treasure map
	[1041516] = true; -- a youthful treasure map
	[1041517] = true; -- a plainly drawn treasure map
	[1041518] = true; -- an expertly drawn treasure map
	[1041519] = true; -- an adeptly drawn treasure map
	[1041520] = true; -- a cleverly drawn treasure map
	[1041521] = true; -- a deviously drawn treasure map
	[1063453] = true; -- an ingeniously drawn treasure map
}

CourseMapWindow.isTmap = false
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function CourseMapWindow.Initialize()
    local mapId = SystemData.ActiveObject.Id
    local windowName = "CourseMapWindow"..mapId
    
    CourseMapWindow.NumPointsCreated[mapId] = 0
    CourseMapWindow.MapPoints[mapId] = {}
    
    Interface.DestroyWindowOnClose[windowName] = true
    
    WindowSetId(windowName,mapId)
    WindowRegisterEventHandler(windowName,SystemData.Events.COURSE_MAP_DATA_UPDATED,"CourseMapWindow.UpdatePoints")
    WindowRegisterEventHandler(windowName,SystemData.Events.COURSE_MAP_STATE_UPDATED,"CourseMapWindow.UpdateState")
    
    local width, height, textureWidth, textureHeight, textureScale = GetCourseMapWindowDimensions(mapId)
    
    if( width ~= nil and height ~= nil and textureScale ~= nil ) then
        WindowSetDimensions(windowName, width + CourseMapWindow.X_PADDING, height + CourseMapWindow.Y_PADDING)
        WindowSetDimensions(windowName.."Texture", width, height)
        DynamicImageSetTextureDimensions(windowName.."Texture", textureWidth, textureHeight)
        DynamicImageSetTextureScale(windowName.."Texture", textureScale)
        DynamicImageSetTexture(windowName.."Texture", "CourseMap"..mapId, 0, 0)
        
        local topWidth, topHeight = WindowGetDimensions(windowName.."Top")
        topWidth = width + 25
        WindowSetDimensions(windowName.."Top",topWidth,topHeight)
        
        local bottomWidth, bottomHeight = WindowGetDimensions(windowName.."Bottom")
        bottomWidth = width + CourseMapWindow.X_PADDING
        WindowSetDimensions(windowName.."Bottom",bottomWidth,bottomHeight) 
    end
    
    LabelSetText(windowName.."PlotToggle", GetStringFromTid(CourseMapWindow.TID.PlotCourse))
    LabelSetText(windowName.."ClearCourse", GetStringFromTid(CourseMapWindow.TID.ClearCourse))
    WindowSetShowing(windowName.."ClearCourse", false)
    
    RegisterWindowData(WindowData.ItemProperties.Type, mapId)
    if WindowData.ItemProperties[mapId] and WindowData.ItemProperties[mapId].PropertiesTids then 
		CourseMapWindow.isTmap = CourseMapWindow.TreasureMaps[WindowData.ItemProperties[mapId].PropertiesTids[1]]
	end
	UnregisterWindowData(WindowData.ItemProperties.Type, mapId)
  
	if ( CourseMapWindow.isTmap ) then
		WindowSetShowing(windowName.."PlotToggle", false)
		WindowSetShowing(windowName.."ClearCourse", false)
	end
    
    local scale = WindowGetScale(windowName)
	WindowSetScale(windowName, scale * CourseMapWindow.WINDOWSCALE)
end

function CourseMapWindow.Shutdown()
    local mapId = WindowGetId(SystemData.ActiveWindow.name)
    ReleaseCourseMap(mapId)
    CourseMapWindow.MapPoints[mapId] = nil
    CourseMapWindow.NumPointsCreated[mapId] = nil
end

function CourseMapWindow.OnUpdate()
	if(CourseMapWindow.DragMapPoint ~= "") then
		if(WindowGetMoving(CourseMapWindow.DragMapPoint) == false) then
			local windowName = CourseMapWindow.DragMapPoint
			local parentWindow = WindowGetParent(windowName)
			local mapId = WindowGetId(parentWindow)
			local mapPointId = WindowGetId(CourseMapWindow.DragMapPoint)
			
			local textureWidth, textureHeight = WindowGetDimensions(parentWindow.."Texture")
			local point, relativePoint, relativeTo, xOffset, yOffset = WindowGetAnchor(CourseMapWindow.DragMapPoint, 1)
			xOffset = xOffset + CourseMapWindow.X_MAPPOINT_PADDING
			yOffset = yOffset + CourseMapWindow.Y_MAPPOINT_PADDING
			
			if(xOffset >= 0 and xOffset <= textureWidth and yOffset >= 0 and yOffset <= textureHeight) then
				CourseMapMovePoint(mapId, mapPointId, xOffset, yOffset)
			else
				CourseMapDeletePoint(mapId, mapPointId)
			end
			
			CourseMapWindow.DragMapPoint = ""
		end
	end
end

function CourseMapWindow.UpdatePoints()
    local mapId = SystemData.ActiveObject.Id
    local windowName = "CourseMapWindow"..mapId
    
    for i=1, CourseMapWindow.NumPointsCreated[mapId] do
        local mapPointName = windowName..mapId.."Point"..i
        WindowSetShowing(mapPointName,false)
    end

    CourseMapWindow.MapPoints[mapId] = {}
    local xPosVec, yPosVec = GetCourseMapData(mapId)
    if( xPosVec ~= nil and yPosVec ~= nil ) then
        for i=1, table.getn(xPosVec) do
            local mapPointName = windowName..mapId.."Point"..i
            
            CourseMapWindow.MapPoints[mapId][i] = {}
            CourseMapWindow.MapPoints[mapId][i].x = xPosVec[i]
            CourseMapWindow.MapPoints[mapId][i].y = yPosVec[i]
            
            if( i > CourseMapWindow.NumPointsCreated[mapId] ) then
                CreateWindowFromTemplate(mapPointName,"MapPoint",windowName)
                CourseMapWindow.NumPointsCreated[mapId] = CourseMapWindow.NumPointsCreated[mapId] + 1
            end
            
            WindowSetId(mapPointName, i)
            LabelSetText(mapPointName.."Name", L""..i)
            
			if ( CourseMapWindow.isTmap) then
				WindowSetShowing(mapPointName.."Name", false)
			end
            
            WindowClearAnchors(mapPointName)
            WindowAddAnchor(mapPointName,"topleft",windowName.."Texture","center",xPosVec[i],yPosVec[i])
            WindowSetShowing(mapPointName,true)
        end
    end
end

function CourseMapWindow.UpdateState()
	local mapId = SystemData.ActiveObject.Id
    local windowName = "CourseMapWindow"..mapId
    
    if ( not CourseMapWindow.isTmap) then   
		if(CourseMapIsPlotting(mapId) == true) then
			LabelSetText(windowName.."PlotToggle", GetStringFromTid(CourseMapWindow.TID.StopPlotting))
			LabelSetTextColor(windowName.."PlotToggle", 50, 0, 0)
			WindowSetShowing(windowName.."ClearCourse", true)
		else
			LabelSetText(windowName.."PlotToggle", GetStringFromTid(CourseMapWindow.TID.PlotCourse))
			LabelSetTextColor(windowName.."PlotToggle", 0, 50, 0)
			WindowSetShowing(windowName.."ClearCourse", false)
		end
	end
end

function CourseMapWindow.Map_OnLButtonDown()
	local windowName = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(windowName)
	local mapId = WindowGetId(parentWindow)
	
	if(CourseMapIsPlotting(mapId) == false) then
		WindowSetMoving(parentWindow, true)
	end
end

function CourseMapWindow.Map_OnLButtonUp(flags,x,y)
	local windowName = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(windowName)
	local mapId = WindowGetId(parentWindow)
	local scale = WindowGetScale( parentWindow )
	
	if(CourseMapIsPlotting(mapId) == true) then
		CourseMapAddPoint(mapId, x/scale, y/scale)
	else
		WindowSetMoving(parentWindow, false)
	end
end

function CourseMapWindow.PlotToggle_OnLButtonUp()
	local windowName = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(windowName)
	local mapId = WindowGetId(parentWindow)
	
	CourseMapPlotToggle(mapId)
end

function CourseMapWindow.ClearCourse_OnLButtonUp()
	local windowName = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(windowName)
	local mapId = WindowGetId(parentWindow)
	
	CourseMapClearCourse(mapId)
end

function CourseMapWindow.MapPoint_OnLButtonDown()
	local windowName = SystemData.ActiveWindow.name
	local parentWindow = WindowGetParent(windowName)
	local mapWindow = WindowGetParent(parentWindow)
	local mapId = WindowGetId(mapWindow)

	if(CourseMapIsPlotting(mapId) == true) then
		CourseMapWindow.DragMapPoint = parentWindow
		WindowSetMoving(parentWindow, true)
	end
end