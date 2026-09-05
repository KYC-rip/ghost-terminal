import { useState, useEffect } from 'react';

export function useAddressValidator(ticker: string, network: string, address: string) {
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!address || address.trim().length === 0) {
      setIsValid(null);
      setError(null);
      return;
    }

    const timer = setTimeout(async () => {
      setIsValidating(true);
      setError(null);

      const isSepolia = network.toLowerCase().includes('sepolia') || ticker.toLowerCase() === 'seth';
      const isStagenet = network.toLowerCase().includes('stagenet') || ticker.toLowerCase() === 'sxmr';

      if (isSepolia || isStagenet) {
        let localValid = false;

        if (isSepolia) {
          localValid = /^0x[a-fA-F0-9]{40}$/.test(address.trim());
        }
        else if (isStagenet) {
          localValid = /^[57][0-9a-zA-Z]{90,}$/.test(address.trim());
        }

        setIsValid(localValid);
        if (!localValid) setError(`Invalid address format for ${network}`);

        setIsValidating(false);
        return; 
      }

      try {
        const query = new URLSearchParams({
          ticker,
          network,
          address: address.trim()
        });

        // Routed through the uplink so the address being validated isn't sent to a
        // clearnet server (revealing who you're paying) while on Tor.
        const body = await window.api.proxiedGet(`https://api.kyc.rip/v1/market/validate?${query.toString()}`);
        const res = JSON.parse(body);
        
        if (res.error) {
           setError("Validation service unavailable");
           setIsValid(null); 
        } else {
           setIsValid(res.valid);
           if (!res.valid) setError("Invalid address format for this network");
        }

      } catch (err) {
        console.error("Validation failed", err);
        setError("Network error");
      } finally {
        setIsValidating(false);
      }
    }, 600);

    return () => clearTimeout(timer);

  }, [ticker, network, address]);

  return { isValid, isValidating, error };
}
