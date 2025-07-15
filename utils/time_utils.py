import aiohttp
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

EPOCH_CONVERTER_API = "https://www.epochconverter.com/api/timestamp/"

async def convert_epoch_to_human(epoch: int) -> str:
    """
    Convert an epoch timestamp to a human-readable date using epochconverter.com API.
    Falls back to local conversion if API fails.
    """
    try:
        url = f"{EPOCH_CONVERTER_API}{epoch}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # API returns { "timestamp": ..., "date": "YYYY-MM-DD HH:MM:SS" }
                    return data.get("date", datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        logger.warning(f"EpochConverter API failed: {e}, using local conversion.")
    # Fallback to local conversion
    try:
        return datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logger.error(f"Failed to convert epoch: {e}")
        return str(epoch) 
