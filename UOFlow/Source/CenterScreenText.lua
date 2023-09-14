----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

CenterScreenText = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------
CenterScreenText.EnableIgnoreSummons = true
CenterScreenText.LowHPPercDisabled = false
CenterScreenText.LowHPPETPercDisabled = false

CenterScreenText.LOWHPMEStarted = false
CenterScreenText.LOWHPPetStarted = false
CenterScreenText.LowHPPerc = 35
CenterScreenText.LowPETHPPerc = 35
 
----------------------------------------------------------------
-- CenterScreenText Functions
----------------------------------------------------------------

function CenterScreenText.SendCenterScreenTexture(message)
	
	local mobileData = Interface.GetMobileData(WindowData.PlayerStatus.PlayerId)
	
	if ( message == "serverdown" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_ServerDown", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 480, 60 )
		WindowSetDimensions("CenterScreenTextImage", 480, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 1065
		if (mobileData.Gender == 1) then
			sid = 793
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "gmarrived" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_GMArrived", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 384, 60 )
		WindowSetDimensions("CenterScreenTextImage", 384, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 1055
		if (mobileData.Gender == 1) then
			sid = 784
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "artifact" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Artifact", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 220, 80 )
		WindowSetDimensions("CenterScreenTextImage", 220, 80 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 1097
		if (mobileData.Gender == 1) then
			sid = 823
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "gorgon" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_GorgonLensesAreGone", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 576, 72 )
		WindowSetDimensions("CenterScreenTextImage", 576, 72 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 62
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "machete" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_BoneMacheteIsGone", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 576, 60 )
		WindowSetDimensions("CenterScreenTextImage", 576, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)

		local sid = 567
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "battlebegin" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_BattleBegins", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 360, 60 )
		WindowSetDimensions("CenterScreenTextImage", 360, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 1098
		if (mobileData.Gender == 1) then
			sid = 824
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "battlelost" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_BattleLost", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 360, 60 )
		WindowSetDimensions("CenterScreenTextImage", 360, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		local sid = 1058
		if (mobileData.Gender == 1) then
			sid = 787
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	
	if ( message == "slowed" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_SlowedDown", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 340, 80 )
		WindowSetDimensions("CenterScreenTextImage", 340, 80 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	if ( message == "stoned" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Stoned", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 200, 60 )
		WindowSetDimensions("CenterScreenTextImage", 200, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	if ( message == "free" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_YouAreFree", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 400, 80 )
		WindowSetDimensions("CenterScreenTextImage", 400, 80 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	
	if ( message == "backpackfull" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_BackpackFull", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 380, 80 )
		WindowSetDimensions("CenterScreenTextImage", 380, 80 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "disarmed" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Disarmed", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 360, 60 )
		WindowSetDimensions("CenterScreenTextImage", 360, 60 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "beacon" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Beacon", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 360, 120 )
		WindowSetDimensions("CenterScreenTextImage", 360, 120 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		local sid = 323
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "webbed" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Webbed", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 320, 80 )
		WindowSetDimensions("CenterScreenTextImage", 320, 80 )
		
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		local sid = 327
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "panic" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_Panic", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 240, 92 )
		WindowSetDimensions("CenterScreenTextImage", 240, 92 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		local sid = 1088
		if (mobileData.Gender == 1) then
			sid = 814
		end
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "lowhp" ) and not CenterScreenText.LowHPPercDisabled then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_LowLife", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 340, 72 )
		WindowSetDimensions("CenterScreenTextImage", 340, 72 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 0.6, false, 0, 0)
		CenterScreenText.LOWHPMEStarted = true
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "lowhppet" and not CenterScreenText.LOWHPMEStarted) and not CenterScreenText.LowHPPETPercDisabled then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_LowPetLife", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 340, 72 )
		WindowSetDimensions("CenterScreenTextImage", 340, 72 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 0.8, false, 0, 0)
		CenterScreenText.LOWHPPetStarted = true
	end
	
	if ( message == "honorwearoff" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_HonorWearsOff", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 420, 72 )
		WindowSetDimensions("CenterScreenTextImage", 420, 72 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		local sid = 1383
		PlaySound(1, sid, WindowData.PlayerLocation.x,WindowData.PlayerLocation.y,WindowData.PlayerLocation.z)
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
	
	if ( message == "bloodoath" ) then
		DynamicImageSetTexture( "CenterScreenTextImage", "CST_BloodOath", 0, 0 )
		DynamicImageSetTextureDimensions( "CenterScreenTextImage", 360, 88 )
		WindowSetDimensions("CenterScreenTextImage", 360, 88 )
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
		WindowStartAlphaAnimation("CenterScreenTextImage", Window.AnimationType.LOOP, 0.5, 1, 1, false, 0, 3)
		
		CenterScreenText.LOWHPMEStarted = false
		CenterScreenText.LOWHPPetStarted = false
	end
end

function CenterScreenText.OnUpdate(timePassed)
	local lowlifeCount = 0
	for mobileId, dc in pairs(MobilesOnScreen.ReversePet) do		
		local mobileData = Interface.GetMobileData(mobileId)
		if mobileData then
			local curHealth = mobileData.CurrentHealth
			local maxHealth = mobileData.MaxHealth
			local perc = math.floor((curHealth/maxHealth)*100)
			if (tostring(perc) == "-1.#IND") then
				perc = 0
			end
			local show = not Interface.LowHPPETPercDisabled
			if (MobilesOnScreen.IsSummon(name) and CenterScreenText.EnableIgnoreSummons) then
				show = false
			end
			if ( MobilesOnScreen.IsPet(mobileId) and perc > 0 and show) then
				if perc <=CenterScreenText.LowPETHPPerc then
					lowlifeCount = lowlifeCount + 1
				end
			end
		end
	end
	if lowlifeCount > 0 and not CenterScreenText.LOWHPPetStarted then
		CenterScreenText.SendCenterScreenTexture("lowhppet")
		CenterScreenText.LOWHPPetStarted = true
	elseif CenterScreenText.LOWHPPetStarted and lowlifeCount <= 0 then
		CenterScreenText.LOWHPPetStarted = false
		WindowStopAlphaAnimation("CenterScreenTextImage")
		WindowSetAlpha("CenterScreenTextImage", 0)
	end
end