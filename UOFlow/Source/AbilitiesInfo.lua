
AbilitiesInfo = {}


AbilitiesInfo.Data = {
[1] = { name="Armor Ignore", Mana=30 };
[2] = { name="Bleed Attack", Mana=30 };
[3] = { name="Concussion Blow", Mana=20 };
[4] = { name="Crushing Blow", Mana=20 };
[5] = { name="Disarm", Mana=20 };
[6] = { name="Dismount", Mana=35 };
[7] = { name="Double Strike", Mana=30 };
[8] = { name="Infectious Strike", Mana=20 };
[9] = { name="Mortal Strike", Mana=30 };
[10] = { name="Moving Shot", Mana=20 };
[11] = { name="Paralyzing Blow", Mana=30 };
[12] = { name="Shadow Strike", Mana=20 };
[13] = { name="Whirlwind Attack", Mana=15 };
[14] = { name="Riding Swipe", Mana=25 };
[15] = { name="Frenzied Whirlwind", Mana=5 };
[16] = { name="Block", Mana=20 };
[17] = { name="Defense Mastery", Mana=20 };
[18] = { name="Nerve Strike", Mana=30 };
[19] = { name="Talon Strike", Mana=20 };
[20] = { name="Feint", Mana=30 };
[21] = { name="Dual Wield", Mana=20 };
[22] = { name="Double Shot", Mana=35 };
[23] = { name="Armor Pierce", Mana=30 };
[24] = { name="Bladeweave", Mana=15 };
[25] = { name="Force Arrow", Mana=20 };
[26] = { name="Lightning Arrow", Mana=15 };
[27] = { name="Psychic Attack", Mana=25 };
[28] = { name="Serpent Arrow", Mana=25 };
[29] = { name="Force of Nature", Mana=30 };
[30] = { name="Infused Throw", Mana=25 };
[31] = { name="Mystic Arc", Mana=20 };
}

AbilitiesInfo.MessageToID = {
[1060077] = 1; -- The blow penetrated your armor!
[1060160] = 2; -- You are bleeding!
[1060166] = 3; -- You feel disoriented!
[1060091] = 4; --You take extra damage from the crushing attack!
[1060093] = 5; -- Your weapon has been disarmed!
[1060083] = 6; -- You fall off of your mount and take damage!
[1060085] = 7; -- Your attacker strikes with lightning speed! 
[1060081] = 8; -- The poison seems extra effective!
[1060087] = 9; -- You have been mortally wounded!
-- NO MOVING SHOT
[1060164] = 11; -- The attack has temporarily paralyzed you!
[1060079] = 12; -- You are dazed by the attack and your attacker vanishes!
[1060162] = 13; -- You are struck by the whirling attack and take damage!
-- NO RIDING SWIPE
-- NO FRENZIED WHIRLWIND
[1063346] = 16; -- Your attack was blocked!
-- NO DEFENSE MASTERY
[1063357] = 18; -- Your attacker dealt a crippling nerve strike!
[1063359] = 19; -- Your attacker delivers a talon strike!
[1063361] = 20; -- You were deceived by an attacker's feint!
--NO DUAL WIELD
[1063349] = 22; -- You're attacked with a barrage of shots!
[1063351] = 23; -- Your attacker pierced your armor!
-- NO BLADEWEAVE
[1074382] = 25; -- You are struck by a force arrow!
-- NO LIGTNING ARROW
[1074384] = 27; -- Your mind is attacked by psychic force!
-- NO SERPENT ARROW
[1074375] = 29; -- You are assaulted with great force!
[1149564] = 30; -- You are struck by the infused projectile and take damage!
[1149566] = 31; -- You take extra damage from the mystic arc!
}

function AbilitiesInfo.isPrimary(abilityId) 
	return abilityId == EquipmentData.CurrentWeaponAbilities[1]
end

function AbilitiesInfo.RequiresBushido(abilityId) 
	return (abilityId == 18 or abilityId == 14)
end

function AbilitiesInfo.RequiresNinjitsu(abilityId) 
	return (abilityId == 21 or abilityId == 19)
end

function AbilitiesInfo.RequiresBushidoOrNinjitsu(abilityId) 
	return (abilityId == 23 or abilityId == 16 or abilityId == 17 or abilityId == 22 or abilityId == 15)
end

function AbilitiesInfo.CanUse(abilityId) 
	if not abilityId then
		return
	end
	if not WindowData.Paperdoll[WindowData.PlayerStatus.PlayerId] then
		return
	end
	
	local serverId = WindowData.SkillsCSV[50].ServerId
	local sworSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[31].ServerId
	local maceSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[18].ServerId
	local fenceSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[5].ServerId
	local archSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[54].ServerId
	local throSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[51].ServerId
	local tactSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[9].ServerId
	local bushSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[39].ServerId
	local ninjSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	local propMhand = ItemProperties.GetObjectPropertiesTid( WindowData.Paperdoll[WindowData.PlayerStatus.PlayerId][4].slotId, nil, "Abilities Info - check main hand" )
	local propOhand = ItemProperties.GetObjectPropertiesTid( WindowData.Paperdoll[WindowData.PlayerStatus.PlayerId][10].slotId, nil, "Abilities Info - check off-hand" )
	
	local mainReq = 70
	if not AbilitiesInfo.isPrimary(abilityId) then
		mainReq = 90
	end

	if tactSkillLevel < mainReq then
		return false
	end
	
	if AbilitiesInfo.RequiresBushidoOrNinjitsu(abilityId) then
		if bushSkillLevel < 50 and ninjSkillLevel < 50 then
			return false
		end
	elseif AbilitiesInfo.RequiresBushido(abilityId) then
		if bushSkillLevel < 50 then
			return false
		end
	elseif AbilitiesInfo.RequiresNinjitsu(abilityId)  then
		if ninjSkillLevel < 50 then
			return false
		end
	end
	local ubws = false
	if (propMhand) then
		
		for i = 1, table.getn(propMhand) do
			if propMhand[i] == 1060400 then -- ubws
				ubws = true
				break
			end
		end
		if ubws then
			if fenceSkillLevel < mainReq and sworSkillLevel < mainReq and maceSkillLevel < mainReq then
				return false
			end
		else		
			for i = 1, table.getn(propMhand) do
				local lprop = wstring.lower(propMhand[i])
				if propMhand[i] == 1112075 then -- throwing
					if throSkillLevel < mainReq then
						return false
					end
				elseif propMhand[i] == 1061172 then -- swords
					if sworSkillLevel < mainReq then
						return false
					end
				elseif propMhand[i] == 1061173 then -- mace
					if maceSkillLevel < mainReq then
						return false
					end
				elseif propMhand[i] == 1061174 then -- fencing
					if fenceSkillLevel < mainReq then
						return false
					end
				elseif propMhand[i] == 1061175 then -- arcery
					if archSkillLevel < mainReq then
						return false
					end
				end
			end
		end
	elseif (propOhand) then
		for i = 1, table.getn(propOhand) do
			if propOhand[i] == 1060400 then -- ubws
				ubws = true
				break
			end
		end
		if ubws then
			if fenceSkillLevel < mainReq and sworSkillLevel < mainReq and maceSkillLevel < mainReq then
				return false
			end
		else	
			for i = 1, table.getn(propOhand) do
				if propOhand[i] == 1112075 then -- throwing
					if throSkillLevel < mainReq then
						return false
					end
				elseif propOhand[i] == 1061172 then -- swords
					if sworSkillLevel < mainReq then
						return false
					end
				elseif propOhand[i] == 1061173 then -- mace
					if maceSkillLevel < mainReq then
						return false
					end
				elseif propOhand[i] == 1061174 then -- fencing
					if fenceSkillLevel < mainReq then
						return false
					end
				elseif propOhand[i] == 1061175 then -- arcery
					if archSkillLevel < mainReq then
						return false
					end
				elseif propOhand[i] == 1060400 then -- ubws
					if fenceSkillLevel < mainReq and sworSkillLevel < mainReq and maceSkillLevel < mainReq then
						return false
					end
				end
			end
		end
	end
	
	return true

end 

function AbilitiesInfo.GetManaCost(abilityId) 
	--[[
	The Mana Cost of each special move can be reduced if the warrior's skills are high enough. 
	Add up the skill points for Swords, Mace Fighting, Fencing, Archery, Parrying, Lumberjacking, Stealth, Poisoning, Bushido and Ninjitsu. 
	If the total lies between 200 and 299, subtract 5 from the Mana Cost. If the total is 300 or more, subtract 10 from the Mana Cost.
	+ item LMC
	If a special move is attempted performed within 3 seconds after another special move, the mana cost of that move will be doubled.
	--]]
	if not abilityId then
		return
	end
	if not AbilitiesInfo.Data[abilityId] then
		return
	end
	
	local manaCost = AbilitiesInfo.Data[abilityId].Mana
	
	
	local lmcItems = tonumber(WindowData.PlayerStatus["LowerManaCost"])
	
	local serverId = WindowData.SkillsCSV[50].ServerId
	local sworSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[31].ServerId
	local maceSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[18].ServerId
	local fenceSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[5].ServerId
	local archSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[54].ServerId
	local throSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[40].ServerId
	local parrSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[30].ServerId
	local lumbSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[49].ServerId
	local steaSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[42].ServerId
	local poisSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[9].ServerId
	local bushSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	serverId = WindowData.SkillsCSV[39].ServerId
	local ninjSkillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue / 10
	
	
	local total = sworSkillLevel + maceSkillLevel + fenceSkillLevel + archSkillLevel + parrSkillLevel + lumbSkillLevel + steaSkillLevel + poisSkillLevel + bushSkillLevel + ninjSkillLevel + throSkillLevel
	if total >= 200 and total <300 then
		lmcItems = lmcItems + 5
	elseif total > 300 then
		lmcItems = lmcItems + 10
	end
	lmcItems = lmcItems / 100
	if Interface.LastSpecialMoveTime > 0 then
		manaCost = manaCost * 2
	end
	return math.ceil(manaCost - math.floor(manaCost * lmcItems))
end




