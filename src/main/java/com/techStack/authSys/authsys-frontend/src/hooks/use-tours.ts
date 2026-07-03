"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { tourApi } from "@/lib/tour-api";
import type { ApiError, TourSummary } from "@/types/tour";

export function useTours() {
  const [tours, setTours] = useState<TourSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await tourApi.getTours(0, 50);
      setTours(data.content);
      setTotal(data.totalElements);
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't load tours.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return { tours, total, isLoading, refetch: load };
}
